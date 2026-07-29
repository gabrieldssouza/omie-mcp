/**
 * Minimal OAuth 2.1 authorization server for the HTTP bridge.
 *
 * Remote MCP clients (claude.ai included) authenticate via OAuth, not via a key
 * in the URL. This module turns the bridge-key screen into an authorization
 * endpoint: each user types the key in the browser and the client receives a
 * personal access token. The key never travels in the connector URL, so the
 * same URL can be distributed to a whole organization — only people who know
 * the key can complete the link.
 *
 * Everything is stateless — codes and tokens are HMAC-signed with a secret
 * derived from MCP_BRIDGE_KEY, so they survive restarts and multiple App
 * Service instances without external storage. Rotating MCP_BRIDGE_KEY (or
 * MCP_TOKEN_SECRET) invalidates every issued token, which is the intended
 * revocation mechanism.
 *
 * References: OAuth 2.1, RFC 7591 (dynamic client registration), RFC 8414
 * (AS metadata), RFC 8707 (resource indicators), RFC 9207 (iss parameter),
 * RFC 9728 (protected resource metadata).
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export const SCOPE = "omie";
export const ACCESS_TOKEN_TTL = 3600;
export const REFRESH_TOKEN_TTL = 90 * 24 * 3600;
export const AUTH_CODE_TTL = 300;

/** Hosts the authorization endpoint may redirect back to after the link.
 *  Restricting this is what keeps /authorize from being an open redirector. */
const DEFAULT_REDIRECT_HOSTS = [
  "claude.ai",
  "www.claude.ai",
  "claude.com",
  "www.claude.com",
  "localhost",
  "127.0.0.1",
];

export class OAuthError extends Error {
  constructor(
    public code: string,
    public description: string,
    public status: number = 400,
  ) {
    super(description);
  }

  toJSON(): Record<string, string> {
    return { error: this.code, error_description: this.description };
  }
}

function b64u(raw: Buffer): string {
  return raw.toString("base64url");
}

function now(): number {
  return Math.floor(Date.now() / 1000);
}

export function deriveSecret(bridgeKey: string): Buffer {
  // MCP_TOKEN_SECRET lets you rotate tokens without changing the key users type.
  const extra = process.env.MCP_TOKEN_SECRET || "";
  return createHash("sha256").update(`omie-mcp\0${bridgeKey}\0${extra}`, "utf8").digest();
}

function sign(payload: Record<string, unknown>, secret: Buffer): string {
  const body = b64u(Buffer.from(JSON.stringify(payload, Object.keys(payload).sort()), "utf8"));
  const signature = b64u(createHmac("sha256", secret).update(body, "ascii").digest());
  return `${body}.${signature}`;
}

function unsign(token: string, secret: Buffer, expectedTyp: string): Record<string, unknown> | null {
  const dot = token.indexOf(".");
  if (dot <= 0 || dot === token.length - 1) return null;
  const body = token.slice(0, dot);
  const signature = token.slice(dot + 1);

  const expected = b64u(createHmac("sha256", secret).update(body, "ascii").digest());
  const sigBuf = Buffer.from(signature, "utf8");
  const expBuf = Buffer.from(expected, "utf8");
  if (sigBuf.length !== expBuf.length || !timingSafeEqual(sigBuf, expBuf)) return null;

  let payload: unknown;
  try {
    payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  } catch {
    return null;
  }
  if (typeof payload !== "object" || payload === null) return null;
  const record = payload as Record<string, unknown>;
  if (record.typ !== expectedTyp) return null;
  if (typeof record.exp !== "number" || record.exp <= now()) return null;
  return record;
}

function allowedRedirectHosts(): Set<string> {
  const configured = (process.env.MCP_ALLOWED_REDIRECT_HOSTS || "").trim();
  if (!configured) return new Set(DEFAULT_REDIRECT_HOSTS);
  return new Set(
    configured
      .split(",")
      .map((h) => h.trim().toLowerCase())
      .filter(Boolean),
  );
}

export interface TokenSet {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  refresh_token: string;
  scope: string;
}

/** Issues and validates bridge credentials. No in-memory state. */
export class OAuthProvider {
  private secret: Buffer;
  private allowedHosts: Set<string>;

  constructor(private bridgeKey: string) {
    this.secret = deriveSecret(bridgeKey);
    this.allowedHosts = allowedRedirectHosts();
  }

  // ------------------------------------------------------------- metadata

  protectedResourceMetadata(baseUrl: string, resourcePath: string): Record<string, unknown> {
    return {
      resource: `${baseUrl}${resourcePath}`,
      authorization_servers: [baseUrl],
      scopes_supported: [SCOPE],
      bearer_methods_supported: ["header"],
    };
  }

  authorizationServerMetadata(baseUrl: string): Record<string, unknown> {
    return {
      issuer: baseUrl,
      authorization_endpoint: `${baseUrl}/authorize`,
      token_endpoint: `${baseUrl}/token`,
      registration_endpoint: `${baseUrl}/register`,
      scopes_supported: [SCOPE],
      response_types_supported: ["code"],
      response_modes_supported: ["query"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      token_endpoint_auth_methods_supported: ["none"],
      code_challenge_methods_supported: ["S256"],
      authorization_response_iss_parameter_supported: true,
    };
  }

  // ------------------------------------------- dynamic client registration

  /** RFC 7591. The client_id is a signed blob embedding the redirect_uris, so
   *  no registration storage is needed to validate the redirect later. */
  registerClient(request: Record<string, unknown>): Record<string, unknown> {
    const redirectUris = request.redirect_uris;
    if (!Array.isArray(redirectUris) || redirectUris.length === 0) {
      throw new OAuthError("invalid_redirect_uri", "redirect_uris is required");
    }
    for (const uri of redirectUris) {
      if (typeof uri !== "string" || !this.isRedirectAllowed(uri)) {
        throw new OAuthError("invalid_redirect_uri", `redirect_uri not allowed: ${uri}`);
      }
    }

    const issuedAt = now();
    const clientId = sign(
      {
        typ: "client",
        ru: redirectUris,
        iat: issuedAt,
        // client_id never really expires, but unsign() requires exp.
        exp: issuedAt + 10 * 365 * 24 * 3600,
      },
      this.secret,
    );

    const response: Record<string, unknown> = {
      client_id: clientId,
      client_id_issued_at: issuedAt,
      redirect_uris: redirectUris,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
      scope: SCOPE,
    };
    if (typeof request.client_name === "string") response.client_name = request.client_name;
    return response;
  }

  // ---------------------------------------------------------- redirect_uri

  isRedirectAllowed(redirectUri: string): boolean {
    let parsed: URL;
    try {
      parsed = new URL(redirectUri);
    } catch {
      return false;
    }
    if (parsed.hash) return false;
    const host = parsed.hostname.toLowerCase();
    if (parsed.protocol === "https:") return this.allowedHosts.has(host);
    // http only for local development
    if (parsed.protocol === "http:") return host === "localhost" || host === "127.0.0.1";
    return false;
  }

  /** If we issued the client_id, the redirect must be among the registered
   *  ones. Foreign client_ids fall back to the host allowlist alone. */
  redirectUriMatchesClient(clientId: string, redirectUri: string): boolean {
    const payload = unsign(clientId, this.secret, "client");
    if (payload === null) return true;
    const registered = payload.ru;
    return Array.isArray(registered) && registered.includes(redirectUri);
  }

  // -------------------------------------------------------------- auth code

  issueCode(opts: {
    clientId: string;
    redirectUri: string;
    codeChallenge: string;
    resource: string;
    scope: string;
  }): string {
    return sign(
      {
        typ: "code",
        cid: opts.clientId,
        ru: opts.redirectUri,
        cc: opts.codeChallenge,
        aud: opts.resource,
        scope: opts.scope,
        jti: randomBytes(8).toString("base64url"),
        exp: now() + AUTH_CODE_TTL,
      },
      this.secret,
    );
  }

  redeemCode(opts: { code: string; codeVerifier: string; redirectUri: string }): Record<string, unknown> {
    const payload = unsign(opts.code, this.secret, "code");
    if (payload === null) throw new OAuthError("invalid_grant", "invalid or expired code");

    if (opts.redirectUri && opts.redirectUri !== payload.ru) {
      throw new OAuthError("invalid_grant", "redirect_uri does not match the code");
    }

    const challenge = typeof payload.cc === "string" ? payload.cc : "";
    if (challenge) {
      if (!opts.codeVerifier) throw new OAuthError("invalid_request", "code_verifier is required");
      const digest = b64u(createHash("sha256").update(opts.codeVerifier, "ascii").digest());
      const a = Buffer.from(digest, "utf8");
      const b = Buffer.from(challenge, "utf8");
      if (a.length !== b.length || !timingSafeEqual(a, b)) {
        throw new OAuthError("invalid_grant", "code_verifier does not match code_challenge");
      }
    }
    return payload;
  }

  // ----------------------------------------------------------------- tokens

  issueTokens(audience: string, scope: string): TokenSet {
    const iat = now();
    const access = sign({ typ: "at", aud: audience, scope, iat, exp: iat + ACCESS_TOKEN_TTL }, this.secret);
    const refresh = sign({ typ: "rt", aud: audience, scope, iat, exp: iat + REFRESH_TOKEN_TTL }, this.secret);
    return {
      access_token: access,
      token_type: "Bearer",
      expires_in: ACCESS_TOKEN_TTL,
      refresh_token: refresh,
      scope,
    };
  }

  refreshTokens(refreshToken: string): TokenSet {
    const payload = unsign(refreshToken, this.secret, "rt");
    if (payload === null) throw new OAuthError("invalid_grant", "invalid or expired refresh_token");
    const audience = typeof payload.aud === "string" ? payload.aud : "";
    const scope = typeof payload.scope === "string" ? payload.scope : SCOPE;
    return this.issueTokens(audience, scope);
  }

  verifyAccessToken(token: string, validAudiences: Set<string>): boolean {
    const payload = unsign(token, this.secret, "at");
    if (payload === null) return false;
    // RFC 8707: the token must have been issued for this resource.
    return typeof payload.aud === "string" && validAudiences.has(payload.aud);
  }

  // --------------------------------------------------------------- helpers

  authorizationRedirect(redirectUri: string, params: Record<string, string>): string {
    const url = new URL(redirectUri);
    for (const [name, value] of Object.entries(params)) url.searchParams.set(name, value);
    return url.toString();
  }

  checkKey(provided: string): boolean {
    const a = Buffer.from(provided, "utf8");
    const b = Buffer.from(this.bridgeKey, "utf8");
    if (a.length !== b.length) {
      // still do a comparison to keep timing flat-ish
      timingSafeEqual(Buffer.alloc(32), Buffer.alloc(32));
      return false;
    }
    return timingSafeEqual(a, b);
  }
}

// ------------------------------------------------------------------ HTML

function escapeHtml(text: string): string {
  return text
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

const LOGIN_PAGE = `<!doctype html>
<html lang="pt-BR">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>omie-mcp bridge</title>
    <style>
        :root { color-scheme: dark; --bg: #0b1220; --text: #e5eefb; --muted: #92a4c3; --accent: #7cc4ff; }
        * { box-sizing: border-box; }
        body {
            margin: 0; min-height: 100vh; display: grid; place-items: center;
            background: radial-gradient(circle at top, #1a2a49 0%, var(--bg) 60%);
            color: var(--text); font-family: Arial, Helvetica, sans-serif; padding: 24px;
        }
        .card {
            width: 100%; max-width: 520px; background: rgba(17, 26, 46, 0.92);
            border: 1px solid rgba(124, 196, 255, 0.22); border-radius: 20px;
            padding: 28px; box-shadow: 0 24px 80px rgba(0, 0, 0, 0.35);
        }
        h1 { margin: 0 0 8px; font-size: 28px; }
        p { margin: 0 0 18px; color: var(--muted); line-height: 1.5; }
        label { display: block; margin: 18px 0 8px; font-weight: 600; }
        input[type=password] {
            width: 100%; border: 1px solid rgba(146, 164, 195, 0.35); border-radius: 12px;
            background: #0b1020; color: var(--text); padding: 14px 16px; font-size: 16px;
            outline: none;
        }
        input[type=password]:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(124, 196, 255, 0.15); }
        button {
            margin-top: 16px; width: 100%; border: 0; border-radius: 12px; padding: 14px 16px;
            background: linear-gradient(135deg, #7cc4ff, #4f8cff); color: #07111f;
            font-weight: 700; font-size: 16px; cursor: pointer;
        }
        .error {
            margin: 0 0 4px; padding: 12px 14px; border-radius: 12px;
            background: rgba(255, 108, 108, 0.12); border: 1px solid rgba(255, 108, 108, 0.4);
            color: #ffb3b3; font-size: 14px;
        }
    </style>
</head>
<body>
    <main class="card">
        <h1>omie-mcp bridge</h1>
        <p>Informe a chave de acesso para liberar este cliente. Cada pessoa faz esse
        vínculo individualmente — a chave não fica salva na URL do conector.</p>
        __ERROR__
        <form method="post" action="__ACTION__">
            <label for="key">Chave de acesso</label>
            <input id="key" name="key" type="password" placeholder="Informe a chave do bridge" autocomplete="off" autofocus required>
            __HIDDEN__
            <button type="submit">Vincular</button>
        </form>
    </main>
</body>
</html>`;

export const INFO_PAGE = `<!doctype html>
<html lang="pt-BR">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>omie-mcp bridge</title>
    <style>
        :root { color-scheme: dark; }
        body {
            margin: 0; min-height: 100vh; display: grid; place-items: center;
            background: radial-gradient(circle at top, #1a2a49 0%, #0b1220 60%);
            color: #e5eefb; font-family: Arial, Helvetica, sans-serif; padding: 24px;
        }
        .card {
            width: 100%; max-width: 560px; background: rgba(17, 26, 46, 0.92);
            border: 1px solid rgba(124, 196, 255, 0.22); border-radius: 20px; padding: 28px;
        }
        h1 { margin: 0 0 12px; font-size: 26px; }
        p { color: #92a4c3; line-height: 1.6; }
    </style>
</head>
<body>
    <main class="card">
        <h1>omie-mcp bridge</h1>
        <p>Este é o endpoint MCP do servidor. Ele não é feito para ser aberto no navegador.</p>
        <p>Adicione esta URL como conector no Claude. A chave de acesso será pedida
        na hora do vínculo, individualmente para cada pessoa.</p>
    </main>
</body>
</html>`;

export function renderLoginPage(opts: {
  action: string;
  hidden: Record<string, string>;
  error?: string;
}): string {
  const hiddenHtml = Object.entries(opts.hidden)
    .filter(([, value]) => Boolean(value))
    .map(
      ([name, value]) =>
        `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`,
    )
    .join("");
  const errorHtml = opts.error ? `<div class="error">${escapeHtml(opts.error)}</div>` : "";
  return LOGIN_PAGE.replace("__ACTION__", escapeHtml(opts.action))
    .replace("__ERROR__", errorHtml)
    .replace("__HIDDEN__", hiddenHtml);
}
