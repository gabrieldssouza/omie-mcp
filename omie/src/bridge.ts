/**
 * HTTP bridge for Azure Web Apps: wraps the MCP streamable-HTTP endpoint with
 * the OAuth 2.1 authorization server from oauth.ts.
 *
 * Auth accepted on /mcp, in order:
 *   1. OAuth Bearer token (what claude.ai uses after the /authorize link flow)
 *   2. Direct key via ?key= or X-Bridge-Key header (own use / quick tests)
 *
 * Everything else (metadata, /register, /authorize, /token) implements the
 * discovery + link flow remote MCP clients expect.
 */

import { randomUUID } from "node:crypto";
import type { Request, Response, Express } from "express";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import type { Server } from "@modelcontextprotocol/sdk/server/index.js";

import { INFO_PAGE, OAuthError, OAuthProvider, SCOPE, renderLoginPage } from "./oauth.js";

const BRIDGE_PATH = "/mcp";

const AUTHORIZE_FIELDS = [
  "client_id",
  "redirect_uri",
  "state",
  "code_challenge",
  "code_challenge_method",
  "scope",
  "resource",
  "response_type",
] as const;

interface AuthorizeParams {
  response_type: string;
  client_id: string;
  redirect_uri: string;
  state: string;
  code_challenge: string;
  code_challenge_method: string;
  scope: string;
  resource: string;
}

function first(value: unknown): string {
  if (Array.isArray(value)) return typeof value[0] === "string" ? value[0] : "";
  return typeof value === "string" ? value : "";
}

/** Public base URL. On App Service TLS terminates at the front end, so the
 *  real scheme arrives in X-Forwarded-Proto. */
function baseUrl(req: Request): string {
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

export function installBridge(app: Express, createSession: () => Promise<Server>): void {
  const bridgeKey = process.env.MCP_BRIDGE_KEY || "omie-mcp-bridge-2026";
  const oauth = new OAuthProvider(bridgeKey);
  const transports = new Map<string, StreamableHTTPServerTransport>();

  const validAudiences = (base: string) => new Set([base, `${base}${BRIDGE_PATH}`, `${base}${BRIDGE_PATH}/`]);

  const authorizeParams = (source: Record<string, unknown>, base: string): AuthorizeParams => ({
    response_type: first(source.response_type) || "code",
    client_id: first(source.client_id),
    redirect_uri: first(source.redirect_uri),
    state: first(source.state),
    code_challenge: first(source.code_challenge),
    code_challenge_method: first(source.code_challenge_method),
    scope: first(source.scope) || SCOPE,
    resource: first(source.resource) || `${base}${BRIDGE_PATH}`,
  });

  /** Returns an error message when the request cannot even be redirected. */
  const validateAuthorize = (params: AuthorizeParams): string => {
    if (!params.redirect_uri) return "redirect_uri is required.";
    if (!oauth.isRedirectAllowed(params.redirect_uri)) {
      return (
        `redirect_uri not allowed: ${params.redirect_uri}. ` +
        "Set MCP_ALLOWED_REDIRECT_HOSTS if this client is legitimate."
      );
    }
    if (!oauth.redirectUriMatchesClient(params.client_id, params.redirect_uri)) {
      return "redirect_uri does not match the one registered for this client_id.";
    }
    return "";
  };

  const hiddenFields = (params: AuthorizeParams): Record<string, string> =>
    Object.fromEntries(AUTHORIZE_FIELDS.map((name) => [name, params[name]]));

  // ------------------------------------------------------------------ CORS

  app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    if (req.method === "OPTIONS") {
      res
        .status(204)
        .setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        .setHeader(
          "Access-Control-Allow-Headers",
          "content-type, authorization, mcp-session-id, mcp-protocol-version, x-bridge-key",
        )
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

  app.get("/authorize", (req, res) => {
    const base = baseUrl(req);
    const params = authorizeParams(req.query as Record<string, unknown>, base);

    const problem = validateAuthorize(params);
    if (problem) {
      res.status(400).type("text/plain").send(problem);
      return;
    }
    if (params.response_type !== "code") {
      res.redirect(
        302,
        oauth.authorizationRedirect(params.redirect_uri, {
          error: "unsupported_response_type",
          iss: base,
          ...(params.state ? { state: params.state } : {}),
        }),
      );
      return;
    }
    if (params.code_challenge && params.code_challenge_method && params.code_challenge_method !== "S256") {
      res.redirect(
        302,
        oauth.authorizationRedirect(params.redirect_uri, {
          error: "invalid_request",
          iss: base,
          ...(params.state ? { state: params.state } : {}),
        }),
      );
      return;
    }

    res
      .status(200)
      .setHeader("Cache-Control", "no-store")
      .type("html")
      .send(renderLoginPage({ action: `${base}/authorize`, hidden: hiddenFields(params) }));
  });

  app.post("/authorize", (req, res) => {
    const base = baseUrl(req);
    const form = (req.body ?? {}) as Record<string, unknown>;
    const params = authorizeParams(form, base);

    const problem = validateAuthorize(params);
    if (problem) {
      res.status(400).type("text/plain").send(problem);
      return;
    }

    if (!oauth.checkKey(first(form.key))) {
      res
        .status(401)
        .setHeader("Cache-Control", "no-store")
        .type("html")
        .send(
          renderLoginPage({
            action: `${base}/authorize`,
            hidden: hiddenFields(params),
            error: "Chave incorreta. Tente novamente.",
          }),
        );
      return;
    }

    const code = oauth.issueCode({
      clientId: params.client_id,
      redirectUri: params.redirect_uri,
      codeChallenge: params.code_challenge,
      resource: params.resource,
      scope: params.scope,
    });
    res.redirect(
      302,
      oauth.authorizationRedirect(params.redirect_uri, {
        code,
        iss: base,
        ...(params.state ? { state: params.state } : {}),
      }),
    );
  });

  // ------------------------------------------------------------------ token

  app.post("/token", (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    const form = (req.body ?? {}) as Record<string, unknown>;
    const grantType = first(form.grant_type);

    try {
      if (grantType === "authorization_code") {
        const payload = oauth.redeemCode({
          code: first(form.code),
          codeVerifier: first(form.code_verifier),
          redirectUri: first(form.redirect_uri),
        });
        const audience = typeof payload.aud === "string" ? payload.aud : `${baseUrl(req)}${BRIDGE_PATH}`;
        const scope = typeof payload.scope === "string" ? payload.scope : SCOPE;
        res.json(oauth.issueTokens(audience, scope));
      } else if (grantType === "refresh_token") {
        res.json(oauth.refreshTokens(first(form.refresh_token)));
      } else {
        throw new OAuthError("unsupported_grant_type", `unsupported grant_type: ${grantType || "(empty)"}`);
      }
    } catch (err) {
      if (err instanceof OAuthError) res.status(err.status).json(err.toJSON());
      else res.status(500).json({ error: "server_error" });
    }
  });

  // --------------------------------------------------------- /mcp endpoint

  const isAuthorized = (req: Request): boolean => {
    const queryKey = first((req.query as Record<string, unknown>).key);
    const headerKey = first(req.headers["x-bridge-key"]);
    if ((queryKey && oauth.checkKey(queryKey)) || (headerKey && oauth.checkKey(headerKey))) return true;

    const authorization = first(req.headers.authorization);
    if (authorization.toLowerCase().startsWith("bearer ")) {
      const token = authorization.slice(7).trim();
      return oauth.verifyAccessToken(token, validAudiences(baseUrl(req)));
    }
    return false;
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
