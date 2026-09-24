/**
 * HTTP bridge for Azure Web Apps: wraps the MCP streamable-HTTP endpoint with
 * the OAuth 2.1 authorization server from oauth.ts, which delegates the login
 * to Microsoft Entra ID (entra.ts).
 *
 * Link flow when someone clicks "Connect" in Claude:
 *   Claude → /authorize → Microsoft SSO → /auth/callback (group check)
 *   → Claude's redirect_uri with a code → /token → Bearer token on /mcp.
 *
 * /mcp only accepts that Bearer token — there is no shared key anymore.
 */

import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { Request, Response, Express } from "express";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import type { Server } from "@modelcontextprotocol/sdk/server/index.js";

import { EntraClient, EntraError, describeEntraError, pkcePair } from "./entra.js";
import { INFO_PAGE, OAuthError, OAuthProvider, SCOPE, renderPage } from "./oauth.js";
import type { PendingAuthorization } from "./oauth.js";

const BRIDGE_PATH = "/mcp";
const CALLBACK_PATH = "/auth/callback";
const LOGIN_COOKIE = "omie_mcp_login";

function first(value: unknown): string {
  if (Array.isArray(value)) return typeof value[0] === "string" ? value[0] : "";
  return typeof value === "string" ? value : "";
}

/** Public base URL. MCP_PUBLIC_URL pins it (it must match the redirect URI
 *  registered in Entra); otherwise on App Service TLS terminates at the front
 *  end, so the real scheme arrives in X-Forwarded-Proto. */
function baseUrl(req: Request): string {
  const pinned = (process.env.MCP_PUBLIC_URL || "").trim().replace(/\/+$/, "");
  if (pinned) return pinned;
  const forwardedProto = first(req.headers["x-forwarded-proto"]).split(",")[0].trim();
  const scheme = forwardedProto || req.protocol || "http";
  const forwardedHost = first(req.headers["x-forwarded-host"]).split(",")[0].trim();
  const host = forwardedHost || first(req.headers.host);
  return `${scheme}://${host}`;
}

function isHtmlRequest(req: Request): boolean {
  const accept = first(req.headers.accept).toLowerCase();
  return accept.includes("text/html") && !accept.includes("application/json") && !accept.includes("text/event-stream");
}

function readCookie(req: Request, name: string): string {
  for (const part of first(req.headers.cookie).split(";")) {
    const eq = part.indexOf("=");
    if (eq > 0 && part.slice(0, eq).trim() === name) return decodeURIComponent(part.slice(eq + 1).trim());
  }
  return "";
}

function sha256(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("base64url");
}

export function installBridge(app: Express, createSession: () => Promise<Server>): void {
  const entra = new EntraClient();
  const tokenSecret = process.env.MCP_TOKEN_SECRET || process.env.AZURE_CLIENT_SECRET || "";
  const oauth = new OAuthProvider(tokenSecret);
  const transports = new Map<string, StreamableHTTPServerTransport>();

  const validAudiences = (base: string) => new Set([base, `${base}${BRIDGE_PATH}`, `${base}${BRIDGE_PATH}/`]);

  const errorPage = (res: Response, status: number, message: string): void => {
    res
      .status(status)
      .setHeader("Cache-Control", "no-store")
      .type("html")
      .send(renderPage("Não foi possível vincular", [message], true));
  };

  // ------------------------------------------------------------------ CORS

  app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    if (req.method === "OPTIONS") {
      res
        .status(204)
        .setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        .setHeader("Access-Control-Allow-Headers", "content-type, authorization, mcp-session-id, mcp-protocol-version")
        .setHeader("Access-Control-Max-Age", "86400")
        .end();
      return;
    }
    next();
  });

  // ---------------------------------------------------------------- health

  app.get(["/health", "/healthz"], (_req, res) => {
    res.json({ status: "ok", sessions: transports.size });
  });

  app.get("/", (_req, res) => {
    res.redirect(302, BRIDGE_PATH);
  });

  // -------------------------------------------------------------- metadata

  // RFC 9728 — served on both paths: with and without the resource path.
  app.get(
    ["/.well-known/oauth-protected-resource", `/.well-known/oauth-protected-resource${BRIDGE_PATH}`],
    (req, res) => {
      res.setHeader("Cache-Control", "no-store");
      res.json(oauth.protectedResourceMetadata(baseUrl(req), BRIDGE_PATH));
    },
  );

  // RFC 8414 + OpenID Connect Discovery — the spec requires at least one.
  app.get(
    [
      "/.well-known/oauth-authorization-server",
      `/.well-known/oauth-authorization-server${BRIDGE_PATH}`,
      "/.well-known/openid-configuration",
    ],
    (req, res) => {
      res.setHeader("Cache-Control", "no-store");
      res.json(oauth.authorizationServerMetadata(baseUrl(req)));
    },
  );

  // ---------------------------------------------------- client registration

  app.post("/register", (req, res) => {
    const body = req.body;
    if (typeof body !== "object" || body === null || Array.isArray(body)) {
      res.status(400).json({ error: "invalid_client_metadata" });
      return;
    }
    try {
      res.status(201).json(oauth.registerClient(body as Record<string, unknown>));
    } catch (err) {
      if (err instanceof OAuthError) res.status(err.status).json(err.toJSON());
      else res.status(500).json({ error: "server_error" });
    }
  });

  // -------------------------------------------------------------- authorize

  /** Claude's /authorize request: validate it, park it in a sealed state and
   *  send the browser to the Microsoft login. */
  app.get("/authorize", (req, res) => {
    const base = baseUrl(req);
    const query = req.query as Record<string, unknown>;
    const responseType = first(query.response_type) || "code";
    const codeChallengeMethod = first(query.code_challenge_method);
    const pending: PendingAuthorization = {
      clientId: first(query.client_id),
      redirectUri: first(query.redirect_uri),
      state: first(query.state),
      codeChallenge: first(query.code_challenge),
      resource: first(query.resource) || `${base}${BRIDGE_PATH}`,
      scope: first(query.scope) || SCOPE,
    };

    // Nothing may be redirected back until the redirect_uri itself is trusted.
    if (!pending.redirectUri) {
      res.status(400).type("text/plain").send("redirect_uri is required.");
      return;
    }
    if (!oauth.isRedirectAllowed(pending.redirectUri)) {
      res
        .status(400)
        .type("text/plain")
        .send(
          `redirect_uri not allowed: ${pending.redirectUri}. ` +
            "Set MCP_ALLOWED_REDIRECT_HOSTS if this client is legitimate.",
        );
      return;
    }
    if (!oauth.redirectUriMatchesClient(pending.clientId, pending.redirectUri)) {
      res.status(400).type("text/plain").send("redirect_uri does not match the one registered for this client_id.");
      return;
    }

    const fail = (error: string) =>
      res.redirect(
        302,
        oauth.authorizationRedirect(pending.redirectUri, {
          error,
          iss: base,
          ...(pending.state ? { state: pending.state } : {}),
        }),
      );
    if (responseType !== "code") return fail("unsupported_response_type");
    if (pending.codeChallenge && codeChallengeMethod && codeChallengeMethod !== "S256") return fail("invalid_request");

    // Binds the login to this browser: the callback must present the cookie.
    const browserNonce = randomBytes(24).toString("base64url");
    const pkce = pkcePair();
    const nonce = randomBytes(16).toString("base64url");
    const state = oauth.issueLoginState({
      pending,
      entraVerifier: pkce.verifier,
      nonce,
      browser: sha256(browserNonce),
    });

    res.cookie(LOGIN_COOKIE, browserNonce, {
      httpOnly: true,
      secure: base.startsWith("https://"),
      sameSite: "lax",
      path: CALLBACK_PATH,
      maxAge: 10 * 60 * 1000,
    });
    res
      .setHeader("Cache-Control", "no-store")
      .redirect(
        302,
        entra.authorizeUrl({ redirectUri: `${base}${CALLBACK_PATH}`, state, nonce, codeChallenge: pkce.challenge }),
      );
  });

  /** Microsoft redirects here after the SSO. On success the user goes back to
   *  Claude with our authorization code. */
  app.get(CALLBACK_PATH, async (req, res) => {
    const base = baseUrl(req);
    const query = req.query as Record<string, unknown>;
    res.clearCookie(LOGIN_COOKIE, { path: CALLBACK_PATH });

    const login = oauth.openLoginState(first(query.state));
    if (!login) {
      errorPage(res, 400, "O link de login expirou ou é inválido. Volte ao Claude e clique em Conectar novamente.");
      return;
    }
    const browserNonce = readCookie(req, LOGIN_COOKIE);
    if (!browserNonce || sha256(browserNonce) !== login.browser) {
      errorPage(res, 400, "Este login foi iniciado em outro navegador. Volte ao Claude e clique em Conectar novamente.");
      return;
    }

    const { pending } = login;
    const backToClaude = (params: Record<string, string>) =>
      oauth.authorizationRedirect(pending.redirectUri, {
        ...params,
        iss: base,
        ...(pending.state ? { state: pending.state } : {}),
      });

    const entraError = first(query.error);
    if (entraError) {
      const description = first(query.error_description);
      console.error(`SSO recusado: ${entraError} ${description}`);
      errorPage(res, 403, describeEntraError(entraError, description));
      return;
    }

    try {
      const result = await entra.redeemCode({
        code: first(query.code),
        redirectUri: `${base}${CALLBACK_PATH}`,
        codeVerifier: login.entraVerifier,
        nonce: login.nonce,
      });
      console.error(`SSO ok: ${result.identity.email}`);
      const code = oauth.issueCode(pending, result.identity, result.refreshToken);
      res.setHeader("Cache-Control", "no-store").redirect(302, backToClaude({ code }));
    } catch (err) {
      if (err instanceof EntraError) {
        console.error(`SSO negado: ${err.code} ${err.message}`);
        errorPage(res, 403, err.code === "access_denied" ? describeEntraError(err.code, err.message) : err.message);
      } else {
        console.error("SSO falhou:", err);
        errorPage(res, 502, "Falha ao falar com a Microsoft. Tente novamente em instantes.");
      }
    }
  });

  // ------------------------------------------------------------------ token

  app.post("/token", async (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    const form = (req.body ?? {}) as Record<string, unknown>;
    const grantType = first(form.grant_type);

    try {
      if (grantType === "authorization_code") {
        const grant = oauth.redeemCode({
          code: first(form.code),
          codeVerifier: first(form.code_verifier),
          redirectUri: first(form.redirect_uri),
        });
        const audience = grant.audience || `${baseUrl(req)}${BRIDGE_PATH}`;
        res.json(oauth.issueTokens(audience, grant.scope, grant.identity, grant.entraRefreshToken));
      } else if (grantType === "refresh_token") {
        const grant = oauth.openRefreshToken(first(form.refresh_token));
        // Ask Entra again: a user removed from the group loses access here.
        let renewed;
        try {
          renewed = await entra.refresh(grant.entraRefreshToken);
        } catch (err) {
          if (err instanceof EntraError) {
            console.error(`Refresh negado para ${grant.identity.email}: ${err.code} ${err.message}`);
            throw new OAuthError("invalid_grant", "sessão Microsoft expirada ou sem acesso; vincule novamente");
          }
          throw err;
        }
        res.json(oauth.issueTokens(grant.audience, grant.scope, renewed.identity, renewed.refreshToken));
      } else {
        throw new OAuthError("unsupported_grant_type", `unsupported grant_type: ${grantType || "(empty)"}`);
      }
    } catch (err) {
      if (err instanceof OAuthError) res.status(err.status).json(err.toJSON());
      else {
        console.error("Erro no /token:", err);
        res.status(500).json({ error: "server_error" });
      }
    }
  });

  // --------------------------------------------------------- /mcp endpoint

  const isAuthorized = (req: Request): boolean => {
    const authorization = first(req.headers.authorization);
    if (!authorization.toLowerCase().startsWith("bearer ")) return false;
    const token = authorization.slice(7).trim();
    return oauth.verifyAccessToken(token, validAudiences(baseUrl(req))) !== null;
  };

  const deny = (req: Request, res: Response): void => {
    // A browser with no credential gets an explanation instead of a raw 401.
    if (req.method === "GET" && isHtmlRequest(req)) {
      res.status(200).setHeader("Cache-Control", "no-store").type("html").send(INFO_PAGE);
      return;
    }
    const challenge =
      `Bearer resource_metadata="${baseUrl(req)}/.well-known/oauth-protected-resource${BRIDGE_PATH}", ` +
      `scope="${SCOPE}"`;
    res.status(401).setHeader("WWW-Authenticate", challenge).type("text/plain").send("Unauthorized");
  };

  app.post(BRIDGE_PATH, async (req, res) => {
    if (!isAuthorized(req)) {
      deny(req, res);
      return;
    }
    const sessionId = first(req.headers["mcp-session-id"]);
    const existing = sessionId ? transports.get(sessionId) : undefined;
    if (existing) {
      await existing.handleRequest(req, res, req.body);
      return;
    }
    if (!sessionId && isInitializeRequest(req.body)) {
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        enableJsonResponse: true,
        onsessioninitialized: (id) => {
          transports.set(id, transport);
        },
      });
      transport.onclose = () => {
        if (transport.sessionId) transports.delete(transport.sessionId);
      };
      const session = await createSession();
      await session.connect(transport);
      await transport.handleRequest(req, res, req.body);
      return;
    }
    res.status(400).json({ jsonrpc: "2.0", error: { code: -32000, message: "Bad Request" }, id: null });
  });

  app.get(BRIDGE_PATH, async (req, res) => {
    if (!isAuthorized(req)) {
      deny(req, res);
      return;
    }
    const sessionId = first(req.headers["mcp-session-id"]);
    const transport = sessionId ? transports.get(sessionId) : undefined;
    if (transport) await transport.handleRequest(req, res);
    else res.status(400).type("text/plain").send("Invalid session");
  });

  app.delete(BRIDGE_PATH, async (req, res) => {
    if (!isAuthorized(req)) {
      deny(req, res);
      return;
    }
    const sessionId = first(req.headers["mcp-session-id"]);
    const transport = sessionId ? transports.get(sessionId) : undefined;
    if (transport) await transport.handleRequest(req, res);
    else res.status(400).type("text/plain").send("Invalid session");
  });
}
