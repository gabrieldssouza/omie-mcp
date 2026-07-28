"""Authorization server OAuth 2.1 mínimo para o bridge HTTP.

Clientes MCP remotos (claude.ai entre eles) autenticam por OAuth, não por key na URL.
Este módulo transforma a tela de key em um `authorization_endpoint`: cada usuário digita
a key no navegador e recebe um access token pessoal. A key nunca circula na URL do
conector, então a mesma URL pode ser distribuída para a organização inteira e só quem
souber a key consegue concluir o vínculo.

Tudo é stateless — códigos e tokens são assinados com HMAC derivado da MCP_BRIDGE_KEY,
então sobrevivem a restart e a múltiplas instâncias do App Service sem storage externo.
Trocar a MCP_BRIDGE_KEY invalida todos os tokens já emitidos, o que é o comportamento
desejado para revogar acesso.

Referências: OAuth 2.1, RFC 7591 (registro dinâmico), RFC 8414 (metadata do AS),
RFC 8707 (resource indicators), RFC 9207 (parâmetro iss) e RFC 9728 (metadata do
recurso protegido).
"""

import hashlib
import hmac
import html
import json
import os
import secrets
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode
from urllib.parse import urlencode, urlsplit

SCOPE = "omie"
ACCESS_TOKEN_TTL = 3600
REFRESH_TOKEN_TTL = 90 * 24 * 3600
AUTH_CODE_TTL = 300

# Para onde o authorization_endpoint aceita redirecionar depois do vínculo. Restringir
# isso é o que impede o endpoint de ser usado como open redirector.
DEFAULT_REDIRECT_HOSTS = (
    "claude.ai",
    "www.claude.ai",
    "claude.com",
    "www.claude.com",
    "localhost",
    "127.0.0.1",
)

LOGIN_PAGE = """<!doctype html>
<html lang="pt-BR">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>omie-mcp bridge</title>
    <style>
        :root { color-scheme: dark; --bg: #0b1220; --panel: #111a2e; --text: #e5eefb; --muted: #92a4c3; --accent: #7cc4ff; }
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
        .client { margin-top: 18px; font-size: 13px; color: var(--muted); }
    </style>
</head>
<body>
    <main class="card">
        <h1>omie-mcp bridge</h1>
        <p>__INTRO__</p>
        __ERROR__
        <form method="post" action="__ACTION__">
            <label for="key">Chave de acesso</label>
            <input id="key" name="key" type="password" placeholder="Informe a chave do bridge" autocomplete="off" autofocus required>
            __HIDDEN__
            <button type="submit">Vincular</button>
        </form>
        __CLIENT__
    </main>
</body>
</html>"""


def _b64u(raw: bytes) -> str:
    return urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64u_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return urlsafe_b64decode(text + padding)


def _now() -> int:
    return int(time.time())


def derive_secret(bridge_key: str) -> bytes:
    """Deriva a chave de assinatura. MCP_TOKEN_SECRET permite rotacionar tokens sem
    trocar a key que os usuários digitam (e vice-versa)."""
    extra = os.getenv("MCP_TOKEN_SECRET", "")
    return hashlib.sha256(f"omie-mcp\0{bridge_key}\0{extra}".encode("utf-8")).digest()


def _sign(payload: dict, secret: bytes) -> str:
    body = _b64u(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signature = _b64u(hmac.new(secret, body.encode("ascii"), hashlib.sha256).digest())
    return f"{body}.{signature}"


def _unsign(token: str, secret: bytes, expected_typ: str) -> dict | None:
    """Valida assinatura, tipo e expiração. Devolve o payload ou None."""
    body, _, signature = token.partition(".")
    if not body or not signature:
        return None

    expected = _b64u(hmac.new(secret, body.encode("ascii"), hashlib.sha256).digest())
    if not hmac.compare_digest(signature, expected):
        return None

    try:
        payload = json.loads(_b64u_decode(body))
    except (ValueError, TypeError):
        return None

    if not isinstance(payload, dict) or payload.get("typ") != expected_typ:
        return None
    if payload.get("exp", 0) <= _now():
        return None
    return payload


def allowed_redirect_hosts() -> frozenset[str]:
    configured = os.getenv("MCP_ALLOWED_REDIRECT_HOSTS", "")
    if not configured.strip():
        return frozenset(DEFAULT_REDIRECT_HOSTS)
    return frozenset(h.strip().lower() for h in configured.split(",") if h.strip())


class OAuthProvider:
    """Emite e valida credenciais para o bridge. Sem estado em memória."""

    def __init__(self, bridge_key: str) -> None:
        self.bridge_key = bridge_key
        self.secret = derive_secret(bridge_key)
        self.allowed_hosts = allowed_redirect_hosts()

    # ------------------------------------------------------------------ metadata

    def protected_resource_metadata(self, base_url: str, resource_path: str) -> dict:
        return {
            "resource": f"{base_url}{resource_path}",
            "authorization_servers": [base_url],
            "scopes_supported": [SCOPE],
            "bearer_methods_supported": ["header"],
        }

    def authorization_server_metadata(self, base_url: str) -> dict:
        return {
            "issuer": base_url,
            "authorization_endpoint": f"{base_url}/authorize",
            "token_endpoint": f"{base_url}/token",
            "registration_endpoint": f"{base_url}/register",
            "scopes_supported": [SCOPE],
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["none"],
            "code_challenge_methods_supported": ["S256"],
            "authorization_response_iss_parameter_supported": True,
        }

    # ------------------------------------------------------- registro dinâmico

    def register_client(self, request: dict) -> dict:
        """RFC 7591. O client_id é um blob assinado com os redirect_uris dentro, então
        não precisamos guardar registro nenhum para validar o redirect depois."""
        redirect_uris = request.get("redirect_uris")
        if not isinstance(redirect_uris, list) or not redirect_uris:
            raise OAuthError("invalid_redirect_uri", "redirect_uris é obrigatório")

        for uri in redirect_uris:
            if not isinstance(uri, str) or not self.is_redirect_allowed(uri):
                raise OAuthError("invalid_redirect_uri", f"redirect_uri não permitido: {uri}")

        issued_at = _now()
        client_id = _sign(
            {
                "typ": "client",
                "ru": redirect_uris,
                "iat": issued_at,
                # O client_id não expira na prática, mas _unsign exige `exp`.
                "exp": issued_at + 10 * 365 * 24 * 3600,
            },
            self.secret,
        )

        response = {
            "client_id": client_id,
            "client_id_issued_at": issued_at,
            "redirect_uris": redirect_uris,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "scope": SCOPE,
        }
        if isinstance(request.get("client_name"), str):
            response["client_name"] = request["client_name"]
        return response

    # -------------------------------------------------------------- redirect_uri

    def is_redirect_allowed(self, redirect_uri: str) -> bool:
        parts = urlsplit(redirect_uri)
        if parts.fragment:
            return False
        if parts.scheme == "https":
            return (parts.hostname or "").lower() in self.allowed_hosts
        # http só para desenvolvimento local
        if parts.scheme == "http":
            return (parts.hostname or "").lower() in {"localhost", "127.0.0.1"}
        return False

    def redirect_uri_matches_client(self, client_id: str, redirect_uri: str) -> bool:
        """Se o client_id foi emitido por nós, o redirect tem que estar entre os
        registrados. client_id de outra origem cai só no allowlist de hosts."""
        payload = _unsign(client_id, self.secret, "client")
        if payload is None:
            return True
        return redirect_uri in payload.get("ru", [])

    # -------------------------------------------------------------------- código

    def issue_code(self, *, client_id: str, redirect_uri: str, code_challenge: str, resource: str, scope: str) -> str:
        return _sign(
            {
                "typ": "code",
                "cid": client_id,
                "ru": redirect_uri,
                "cc": code_challenge,
                "aud": resource,
                "scope": scope,
                "jti": secrets.token_urlsafe(8),
                "exp": _now() + AUTH_CODE_TTL,
            },
            self.secret,
        )

    def redeem_code(self, *, code: str, code_verifier: str, redirect_uri: str) -> dict:
        payload = _unsign(code, self.secret, "code")
        if payload is None:
            raise OAuthError("invalid_grant", "código inválido ou expirado")

        if redirect_uri and redirect_uri != payload.get("ru"):
            raise OAuthError("invalid_grant", "redirect_uri não corresponde ao do código")

        challenge = payload.get("cc") or ""
        if challenge:
            if not code_verifier:
                raise OAuthError("invalid_request", "code_verifier é obrigatório")
            digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
            if not hmac.compare_digest(_b64u(digest), challenge):
                raise OAuthError("invalid_grant", "code_verifier não corresponde ao code_challenge")

        return payload

    # -------------------------------------------------------------------- tokens

    def issue_tokens(self, *, audience: str, scope: str) -> dict:
        now = _now()
        access = _sign(
            {"typ": "at", "aud": audience, "scope": scope, "iat": now, "exp": now + ACCESS_TOKEN_TTL},
            self.secret,
        )
        refresh = _sign(
            {"typ": "rt", "aud": audience, "scope": scope, "iat": now, "exp": now + REFRESH_TOKEN_TTL},
            self.secret,
        )
        return {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_TTL,
            "refresh_token": refresh,
            "scope": scope,
        }

    def refresh_tokens(self, refresh_token: str) -> dict:
        payload = _unsign(refresh_token, self.secret, "rt")
        if payload is None:
            raise OAuthError("invalid_grant", "refresh_token inválido ou expirado")
        return self.issue_tokens(audience=payload.get("aud", ""), scope=payload.get("scope", SCOPE))

    def verify_access_token(self, token: str, valid_audiences: set[str]) -> bool:
        payload = _unsign(token, self.secret, "at")
        if payload is None:
            return False
        # RFC 8707: o token tem que ter sido emitido para este recurso.
        return payload.get("aud", "") in valid_audiences

    # ------------------------------------------------------------------ resposta

    def authorization_redirect(self, *, redirect_uri: str, params: dict) -> str:
        separator = "&" if urlsplit(redirect_uri).query else "?"
        return f"{redirect_uri}{separator}{urlencode(params)}"

    def check_key(self, provided: str) -> bool:
        return hmac.compare_digest(provided, self.bridge_key)


class OAuthError(Exception):
    def __init__(self, code: str, description: str, status: int = 400) -> None:
        super().__init__(description)
        self.code = code
        self.description = description
        self.status = status

    def to_dict(self) -> dict:
        return {"error": self.code, "error_description": self.description}


def render_login_page(*, action: str, hidden: dict, error: str = "", client_name: str = "") -> str:
    hidden_html = "".join(
        f'<input type="hidden" name="{html.escape(name, quote=True)}" value="{html.escape(value, quote=True)}">'
        for name, value in hidden.items()
        if value
    )
    error_html = f'<div class="error">{html.escape(error)}</div>' if error else ""
    client_html = (
        f'<div class="client">Solicitado por <strong>{html.escape(client_name)}</strong>.</div>' if client_name else ""
    )
    intro = (
        "Informe a chave de acesso para liberar este cliente. Cada pessoa faz esse "
        "vínculo individualmente — a chave não fica salva na URL do conector."
    )
    return (
        LOGIN_PAGE.replace("__ACTION__", html.escape(action, quote=True))
        .replace("__INTRO__", intro)
        .replace("__ERROR__", error_html)
        .replace("__HIDDEN__", hidden_html)
        .replace("__CLIENT__", client_html)
    )
