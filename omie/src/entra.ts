/**
 * Microsoft Entra ID (Azure AD) single sign-on for the bridge.
 *
 * The bridge is a confidential OIDC client of the tenant (app registration
 * "Omie-MCP"). Access is gated twice:
 *   1. In Entra: the enterprise app has "Assignment required" on and only the
 *      allowed group is assigned, so anyone else is stopped at the Microsoft
 *      screen (AADSTS50105).
 *   2. Here, per connector: the id_token must carry one of the connector's
 *      allowed groups in its `groups` claim, or the user's e-mail must be in
 *      its e-mail list (see connectors in bridge.ts). With neither configured
 *      nobody gets in (fail closed).
 *
 * The id_token comes straight from the token endpoint over TLS with client
 * authentication, so per OIDC Core §3.1.3.7 its claims are validated without
 * fetching JWKS for the signature.
 */

import { createHash, randomBytes } from "node:crypto";

import type { Identity } from "./oauth.js";

const LOGIN_HOST = "https://login.microsoftonline.com";
const ENTRA_SCOPES = "openid profile email offline_access";

export class EntraError extends Error {
  constructor(
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

function csv(value: string | undefined): string[] {
  return (value || "")
    .split(",")
    .map((v) => v.trim().toLowerCase())
    .filter(Boolean);
}

function decodeJwtPayload(jwt: string): Record<string, unknown> {
  const parts = jwt.split(".");
  if (parts.length !== 3) throw new EntraError("invalid_id_token", "id_token malformado");
  try {
    return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")) as Record<string, unknown>;
  } catch {
    throw new EntraError("invalid_id_token", "id_token ilegível");
  }
}

export function pkcePair(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier, "ascii").digest("base64url");
  return { verifier, challenge };
}

/** Who may use one connector. */
export interface AccessList {
  groups: Set<string>;
  emails: Set<string>;
}

export function accessListFromEnv(groupsVar: string, emailsVar: string, env: NodeJS.ProcessEnv = process.env): AccessList {
  return { groups: new Set(csv(env[groupsVar])), emails: new Set(csv(env[emailsVar])) };
}

export interface EntraLogin {
  identity: Identity;
  refreshToken: string;
}

export class EntraClient {
  readonly tenantId: string;
  readonly clientId: string;
  private clientSecret: string;

  constructor(env: NodeJS.ProcessEnv = process.env) {
    this.tenantId = (env.AZURE_TENANT_ID || "").trim();
    this.clientId = (env.AZURE_CLIENT_ID || "").trim();
    this.clientSecret = env.AZURE_CLIENT_SECRET || "";

    const missing = ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"].filter((k) => !env[k]);
    if (missing.length) throw new Error(`SSO não configurado: defina ${missing.join(", ")}`);
  }

  private get issuer(): string {
    return `${LOGIN_HOST}/${this.tenantId}/v2.0`;
  }

  authorizeUrl(opts: { redirectUri: string; state: string; nonce: string; codeChallenge: string }): string {
    const url = new URL(`${LOGIN_HOST}/${this.tenantId}/oauth2/v2.0/authorize`);
    url.searchParams.set("client_id", this.clientId);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("response_mode", "query");
    url.searchParams.set("redirect_uri", opts.redirectUri);
    url.searchParams.set("scope", ENTRA_SCOPES);
    url.searchParams.set("state", opts.state);
    url.searchParams.set("nonce", opts.nonce);
    url.searchParams.set("code_challenge", opts.codeChallenge);
    url.searchParams.set("code_challenge_method", "S256");
    url.searchParams.set("prompt", "select_account");
    return url.toString();
  }

  /** Authorization code from the /auth/callback redirect → checked identity. */
  async redeemCode(opts: {
    code: string;
    redirectUri: string;
    codeVerifier: string;
    nonce: string;
    access: AccessList;
  }): Promise<EntraLogin> {
    const tokens = await this.tokenRequest({
      grant_type: "authorization_code",
      code: opts.code,
      redirect_uri: opts.redirectUri,
      code_verifier: opts.codeVerifier,
    });
    return this.checkLogin(tokens, opts.access, opts.nonce);
  }

  /** Re-validates the user with Entra; fails if they were disabled or unassigned. */
  async refresh(refreshToken: string, access: AccessList): Promise<EntraLogin> {
    if (!refreshToken) throw new EntraError("invalid_grant", "sessão sem refresh token da Microsoft");
    const tokens = await this.tokenRequest({ grant_type: "refresh_token", refresh_token: refreshToken });
    // Entra may not rotate the refresh token on every call.
    if (!tokens.refresh_token) tokens.refresh_token = refreshToken;
    return this.checkLogin(tokens, access);
  }

  private async tokenRequest(params: Record<string, string>): Promise<Record<string, string>> {
    const body = new URLSearchParams({
      client_id: this.clientId,
      client_secret: this.clientSecret,
      scope: ENTRA_SCOPES,
      ...params,
    });
    const response = await fetch(`${LOGIN_HOST}/${this.tenantId}/oauth2/v2.0/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body,
    });
    const json = (await response.json().catch(() => ({}))) as Record<string, string>;
    if (!response.ok) {
      throw new EntraError(json.error || "entra_error", json.error_description || `HTTP ${response.status}`);
    }
    return json;
  }

  private checkLogin(tokens: Record<string, string>, access: AccessList, expectedNonce?: string): EntraLogin {
    if (!tokens.id_token) throw new EntraError("invalid_id_token", "a Microsoft não devolveu id_token");
    const claims = decodeJwtPayload(tokens.id_token);
    const now = Math.floor(Date.now() / 1000);

    if (claims.iss !== this.issuer) throw new EntraError("invalid_id_token", "issuer inesperado");
    if (claims.aud !== this.clientId) throw new EntraError("invalid_id_token", "audience inesperada");
    if (claims.tid !== this.tenantId) throw new EntraError("invalid_id_token", "tenant inesperado");
    if (typeof claims.exp !== "number" || claims.exp + 300 < now) {
      throw new EntraError("invalid_id_token", "id_token expirado");
    }
    if (expectedNonce !== undefined && claims.nonce !== expectedNonce) {
      throw new EntraError("invalid_id_token", "nonce não confere");
    }

    const email = String(claims.email || claims.preferred_username || claims.upn || "").toLowerCase();
    const identity: Identity = {
      sub: String(claims.oid || claims.sub || ""),
      email,
      name: String(claims.name || email),
    };
    this.ensureAllowed(claims, identity, access);
    return { identity, refreshToken: tokens.refresh_token || "" };
  }

  private ensureAllowed(claims: Record<string, unknown>, identity: Identity, access: AccessList): void {
    if (identity.email && access.emails.has(identity.email)) return;

    const groups = Array.isArray(claims.groups) ? claims.groups.map((g) => String(g).toLowerCase()) : [];
    if (groups.some((g) => access.groups.has(g))) return;

    const overage = typeof claims._claim_names === "object" || claims.hasgroups === true;
    if (overage) {
      throw new EntraError(
        "access_denied",
        "o token veio sem a lista de grupos (excesso de grupos). Configure groupMembershipClaims=ApplicationGroup no app registration.",
      );
    }
    throw new EntraError("access_denied", `${identity.email || "usuário"} não está no grupo autorizado`);
  }
}

/** Friendly text for the errors a person can actually hit at the SSO screen. */
export function describeEntraError(code: string, description: string): string {
  if (description.includes("AADSTS65004")) {
    return "O login foi cancelado ou não foi concluído. Tente vincular novamente pelo Claude.";
  }
  if (description.includes("AADSTS50105") || code === "access_denied") {
    return "Sua conta não tem acesso a este conector. Peça para incluírem você no grupo de acesso dele no Azure.";
  }
  return `Não foi possível concluir o login com a Microsoft (${code}).`;
}
