/**
 * Minimal OAuth 2.1 authorization server for the HTTP bridge.
 *
 * Remote MCP clients (claude.ai included) need an authorization server that
 * supports Dynamic Client Registration, which Microsoft Entra ID does not. So
 * the bridge is its own authorization server facing Claude, and delegates the
 * actual login to Entra (see entra.ts): /authorize sends the browser to the
 * Microsoft SSO screen, and only members of the allowed group get a code back.
 *
 * Everything is stateless — state, codes and tokens are AES-256-GCM sealed
 * with a key derived from MCP_TOKEN_SECRET (or AZURE_CLIENT_SECRET), so they
 * survive restarts and multiple App Service instances without storage. The
 * Entra refresh token travels sealed inside ours, which lets every refresh
 * re-check the user with Entra: removing someone from the group cuts access
 * within one access-token lifetime. Rotating the secret revokes everything.
 *
 * References: OAuth 2.1, RFC 7591 (dynamic client registration), RFC 8414
 * (AS metadata), RFC 8707 (resource indicators), RFC 9207 (iss parameter),
 * RFC 9728 (protected resource metadata).
 */

import { createCipheriv, createDecipheriv, createHash, randomBytes, timingSafeEqual } from "node:crypto";

export const SCOPE = "omie";
export const ACCESS_TOKEN_TTL = 3600;
export const REFRESH_TOKEN_TTL = 90 * 24 * 3600;
export const AUTH_CODE_TTL = 300;
export const LOGIN_STATE_TTL = 600;

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

/** Who completed the Microsoft login. */
export interface Identity {
  sub: string;
  email: string;
  name: string;
}

function b64u(raw: Buffer): string {
  return raw.toString("base64url");
}

function now(): number {
  return Math.floor(Date.now() / 1000);
}

export function deriveKey(secret: string): Buffer {
  return createHash("sha256").update(`omie-mcp\0${secret}`, "utf8").digest();
}

/** AES-256-GCM: authenticated and confidential, since codes and refresh
 *  tokens carry the user's Entra refresh token. */
function seal(payload: Record<string, unknown>, key: Buffer): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const body = Buffer.concat([cipher.update(JSON.stringify(payload), "utf8"), cipher.final()]);
  return b64u(Buffer.concat([iv, cipher.getAuthTag(), body]));
}

function unseal(token: string, key: Buffer, expectedTyp: string): Record<string, unknown> | null {
  let raw: Buffer;
  try {
    raw = Buffer.from(token, "base64url");
  } catch {
    return null;
  }
  if (raw.length < 29) return null;

  let payload: unknown;
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, raw.subarray(0, 12));
    decipher.setAuthTag(raw.subarray(12, 28));
    const plain = Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]);
    payload = JSON.parse(plain.toString("utf8"));
  } catch {
    return null;
  }
  if (typeof payload !== "object" || payload === null) return null;
  const record = payload as Record<string, unknown>;
  if (record.typ !== expectedTyp) return null;
  if (typeof record.exp !== "number" || record.exp <= now()) return null;
  return record;
}

function str(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function identityOf(payload: Record<string, unknown>): Identity {
  return { sub: str(payload.sub), email: str(payload.email), name: str(payload.name) };
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

/** The /authorize request Claude made, parked while the user is at Microsoft. */
export interface PendingAuthorization {
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
  resource: string;
  scope: string;
}

export interface LoginState {
  pending: PendingAuthorization;
  /** PKCE verifier and nonce of the leg between the bridge and Entra. */
  entraVerifier: string;
  nonce: string;
  /** Hash of the browser-binding cookie, so a state can't be replayed elsewhere. */
  browser: string;
}

/** Issues and validates bridge credentials. No in-memory state. */
export class OAuthProvider {
  private key: Buffer;
  private allowedHosts: Set<string>;

  constructor(secret: string) {
    this.key = deriveKey(secret);
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

  /** RFC 7591. The client_id is a sealed blob embedding the redirect_uris, so
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
    const clientId = seal(
      {
        typ: "client",
        ru: redirectUris,
        iat: issuedAt,
        // client_id never really expires, but unseal() requires exp.
        exp: issuedAt + 10 * 365 * 24 * 3600,
      },
      this.key,
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
    const payload = unseal(clientId, this.key, "client");
    if (payload === null) return true;
    const registered = payload.ru;
    return Array.isArray(registered) && registered.includes(redirectUri);
  }

  // ------------------------------------------------------------ login state

  /** The `state` sent to Entra. Sealed because it carries the PKCE verifier. */
  issueLoginState(state: LoginState): string {
    return seal({ typ: "login", ...state, exp: now() + LOGIN_STATE_TTL }, this.key);
  }

  openLoginState(token: string): LoginState | null {
    const payload = unseal(token, this.key, "login");
    if (payload === null) return null;
    return payload as unknown as LoginState;
  }

  // -------------------------------------------------------------- auth code

  issueCode(pending: PendingAuthorization, identity: Identity, entraRefreshToken: string): string {
    return seal(
      {
        typ: "code",
        cid: pending.clientId,
        ru: pending.redirectUri,
        cc: pending.codeChallenge,
        aud: pending.resource,
        scope: pending.scope,
        ...identity,
        ert: entraRefreshToken,
        jti: randomBytes(8).toString("base64url"),
        exp: now() + AUTH_CODE_TTL,
      },
      this.key,
    );
  }

  redeemCode(opts: { code: string; codeVerifier: string; redirectUri: string }): {
    audience: string;
    scope: string;
    identity: Identity;
    entraRefreshToken: string;
  } {
    const payload = unseal(opts.code, this.key, "code");
    if (payload === null) throw new OAuthError("invalid_grant", "invalid or expired code");

    if (opts.redirectUri && opts.redirectUri !== payload.ru) {
      throw new OAuthError("invalid_grant", "redirect_uri does not match the code");
    }

    const challenge = str(payload.cc);
    if (challenge) {
      if (!opts.codeVerifier) throw new OAuthError("invalid_request", "code_verifier is required");
      const digest = b64u(createHash("sha256").update(opts.codeVerifier, "ascii").digest());
      const a = Buffer.from(digest, "utf8");
      const b = Buffer.from(challenge, "utf8");
      if (a.length !== b.length || !timingSafeEqual(a, b)) {
        throw new OAuthError("invalid_grant", "code_verifier does not match code_challenge");
      }
    }
    return {
      audience: str(payload.aud),
      scope: str(payload.scope) || SCOPE,
      identity: identityOf(payload),
      entraRefreshToken: str(payload.ert),
    };
  }

  // ----------------------------------------------------------------- tokens

  issueTokens(audience: string, scope: string, identity: Identity, entraRefreshToken: string): TokenSet {
    const iat = now();
    const access = seal(
      { typ: "at", aud: audience, scope, ...identity, iat, exp: iat + ACCESS_TOKEN_TTL },
      this.key,
    );
    const refresh = seal(
      { typ: "rt", aud: audience, scope, ...identity, ert: entraRefreshToken, iat, exp: iat + REFRESH_TOKEN_TTL },
      this.key,
    );
    return {
      access_token: access,
      token_type: "Bearer",
      expires_in: ACCESS_TOKEN_TTL,
      refresh_token: refresh,
      scope,
    };
  }

  openRefreshToken(refreshToken: string): {
    audience: string;
    scope: string;
    identity: Identity;
    entraRefreshToken: string;
  } {
    const payload = unseal(refreshToken, this.key, "rt");
    if (payload === null) throw new OAuthError("invalid_grant", "invalid or expired refresh_token");
    return {
      audience: str(payload.aud),
      scope: str(payload.scope) || SCOPE,
      identity: identityOf(payload),
      entraRefreshToken: str(payload.ert),
    };
  }

  /** Returns who the token belongs to, or null if it isn't valid here. */
  verifyAccessToken(token: string, validAudiences: Set<string>): Identity | null {
    const payload = unseal(token, this.key, "at");
    if (payload === null) return null;
    // RFC 8707: the token must have been issued for this resource.
    if (typeof payload.aud !== "string" || !validAudiences.has(payload.aud)) return null;
    return identityOf(payload);
  }

  // --------------------------------------------------------------- helpers

  authorizationRedirect(redirectUri: string, params: Record<string, string>): string {
    const url = new URL(redirectUri);
    for (const [name, value] of Object.entries(params)) url.searchParams.set(name, value);
    return url.toString();
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

const PAGE = `<!doctype html>
<html lang="pt-BR">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>omie-mcp</title>
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
        .error { color: #ffb3b3; }
    </style>
</head>
<body>
    <main class="card">
        <h1>__TITLE__</h1>
        __BODY__
    </main>
</body>
</html>`;

export function renderPage(title: string, paragraphs: string[], isError = false): string {
  const cls = isError ? ' class="error"' : "";
  const body = paragraphs.map((p) => `<p${cls}>${escapeHtml(p)}</p>`).join("\n        ");
  return PAGE.replace("__TITLE__", escapeHtml(title)).replace("__BODY__", body);
}

export const INFO_PAGE = renderPage("omie-mcp", [
  "Este é o endpoint MCP do servidor. Ele não é feito para ser aberto no navegador.",
  "Adicione esta URL como conector no Claude e clique em Conectar: o login é feito " +
    "com a sua conta Microsoft, e só quem está no grupo autorizado do conector consegue acessar.",
]);
