"""MCP Server para integração com o OMIE ERP."""

import json
import os
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from urllib.parse import parse_qs

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from dotenv import load_dotenv

from .client import OmieClient
from .oauth import SCOPE, OAuthError, OAuthProvider, render_login_page
from .tools import fornecedores, contas_pagar, contas_receber, lancamentos_cc, contas_correntes, fluxo_caixa

# Busca .env no diretório atual e em ~/.config/omie-mcp/ (útil para uso via uvx)
load_dotenv()
load_dotenv(os.path.expanduser("~/.config/omie-mcp/.env"))

BRIDGE_PATH = "/mcp"
BRIDGE_KEY = os.getenv("MCP_BRIDGE_KEY", "omie-mcp-bridge-2026")
HTTP_MODE = os.getenv("MCP_TRANSPORT", "").lower() in {"http", "streamable-http", "web"} or bool(os.getenv("PORT"))

INFO_PAGE = """<!doctype html>
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
        code { color: #b9dcff; word-break: break-all; }
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
</html>"""


def _headers_for(body: bytes, content_type: bytes, extra: list[tuple[bytes, bytes]] | None = None) -> list[tuple[bytes, bytes]]:
    headers = [
        (b"content-type", content_type),
        (b"content-length", str(len(body)).encode("ascii")),
    ]
    if extra:
        headers.extend(extra)
    return headers


async def _send_no_content(send, extra_headers: list[tuple[bytes, bytes]]) -> None:
    await send({"type": "http.response.start", "status": 204, "headers": extra_headers})
    await send({"type": "http.response.body", "body": b""})


async def _send_text_response(send, status_code: int, text: str, extra_headers: list[tuple[bytes, bytes]] | None = None) -> None:
    body = text.encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status_code,
            "headers": _headers_for(body, b"text/plain; charset=utf-8", extra_headers),
        }
    )
    await send({"type": "http.response.body", "body": body})


async def _send_html_response(send, status_code: int, markup: str) -> None:
    body = markup.encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status_code,
            "headers": _headers_for(body, b"text/html; charset=utf-8", [(b"cache-control", b"no-store")]),
        }
    )
    await send({"type": "http.response.body", "body": body})


async def _send_json_response(send, status_code: int, payload: dict) -> None:
    body = json.dumps(payload).encode("utf-8")
    extra = [
        (b"cache-control", b"no-store"),
        # Metadata e token podem ser buscados pelo navegador do usuário durante o fluxo.
        (b"access-control-allow-origin", b"*"),
    ]
    await send(
        {
            "type": "http.response.start",
            "status": status_code,
            "headers": _headers_for(body, b"application/json", extra),
        }
    )
    await send({"type": "http.response.body", "body": body})


async def _read_body(receive) -> bytes:
    body = b""
    more_body = True
    while more_body:
        message = await receive()
        if message["type"] != "http.request":
            continue
        body += message.get("body", b"")
        more_body = message.get("more_body", False)
    return body


def _first(params: dict, name: str) -> str:
    values = params.get(name)
    return values[0] if values else ""


class BridgeApp:
    """Wrapper ASGI que protege o endpoint MCP.

    Autentica de duas formas:

    1. OAuth 2.1 (o que o claude.ai usa). O usuário é levado a `/authorize`, digita a
       chave no navegador e o cliente recebe um access token pessoal. A chave nunca
       aparece na URL do conector, então a mesma URL pode ser distribuída para toda a
       organização — só quem souber a chave conclui o vínculo.
    2. Chave direta via `?key=` ou header `X-Bridge-Key`, para uso próprio e testes.
    """

    def __init__(self, inner_app, api_key: str, path_prefix: str = BRIDGE_PATH) -> None:
        self.inner_app = inner_app
        self.api_key = api_key
        self.path_prefix = path_prefix.rstrip("/")
        self.oauth = OAuthProvider(api_key)

    # ------------------------------------------------------------------ utilidades

    @staticmethod
    def _header(scope, header_name: bytes) -> str:
        for raw_name, raw_value in scope.get("headers", []):
            if raw_name.lower() == header_name:
                return raw_value.decode("utf-8", errors="ignore")
        return ""

    def _is_html_request(self, scope) -> bool:
        accept = self._header(scope, b"accept").lower()
        return "text/html" in accept and "application/json" not in accept and "text/event-stream" not in accept

    def _base_url(self, scope) -> str:
        """URL pública do serviço. No App Service o TLS termina no proxy, então o
        esquema real vem em X-Forwarded-Proto."""
        forwarded_proto = self._header(scope, b"x-forwarded-proto").split(",")[0].strip()
        scheme = forwarded_proto or scope.get("scheme", "http")
        host = self._header(scope, b"x-forwarded-host").split(",")[0].strip() or self._header(scope, b"host")
        return f"{scheme}://{host}"

    def _query(self, scope) -> dict:
        return parse_qs(scope.get("query_string", b"").decode("utf-8", errors="ignore"))

    def _valid_audiences(self, base_url: str) -> set[str]:
        return {base_url, f"{base_url}{self.path_prefix}", f"{base_url}{self.path_prefix}/"}

    def _bridge_key_from_scope(self, scope) -> str:
        query_key = _first(self._query(scope), "key")
        return query_key or self._header(scope, b"x-bridge-key")

    def _bearer_token(self, scope) -> str:
        authorization = self._header(scope, b"authorization")
        prefix = "bearer "
        if authorization[: len(prefix)].lower() == prefix:
            return authorization[len(prefix) :].strip()
        return ""

    # -------------------------------------------------------------------- OAuth

    async def _handle_register(self, receive, send) -> None:
        try:
            request = json.loads(await _read_body(receive) or b"{}")
        except ValueError:
            await _send_json_response(send, 400, {"error": "invalid_client_metadata"})
            return
        if not isinstance(request, dict):
            await _send_json_response(send, 400, {"error": "invalid_client_metadata"})
            return

        try:
            await _send_json_response(send, 201, self.oauth.register_client(request))
        except OAuthError as error:
            await _send_json_response(send, error.status, error.to_dict())

    def _authorize_params(self, raw: dict, base_url: str) -> dict:
        return {
            "response_type": _first(raw, "response_type") or "code",
            "client_id": _first(raw, "client_id"),
            "redirect_uri": _first(raw, "redirect_uri"),
            "state": _first(raw, "state"),
            "code_challenge": _first(raw, "code_challenge"),
            "code_challenge_method": _first(raw, "code_challenge_method"),
            "scope": _first(raw, "scope") or SCOPE,
            "resource": _first(raw, "resource") or f"{base_url}{self.path_prefix}",
        }

    def _validate_authorize(self, params: dict) -> str:
        """Devolve mensagem de erro se a requisição não permite nem redirecionar."""
        redirect_uri = params["redirect_uri"]
        if not redirect_uri:
            return "redirect_uri é obrigatório."
        if not self.oauth.is_redirect_allowed(redirect_uri):
            return (
                f"redirect_uri não permitido: {redirect_uri}. "
                "Ajuste MCP_ALLOWED_REDIRECT_HOSTS se o cliente for legítimo."
            )
        if not self.oauth.redirect_uri_matches_client(params["client_id"], redirect_uri):
            return "redirect_uri não corresponde ao registrado para este client_id."
        return ""

    async def _handle_authorize_get(self, scope, send) -> None:
        base_url = self._base_url(scope)
        params = self._authorize_params(self._query(scope), base_url)

        problem = self._validate_authorize(params)
        if problem:
            await _send_text_response(send, 400, problem)
            return

        if params["response_type"] != "code":
            await self._redirect_error(send, params, base_url, "unsupported_response_type")
            return
        if params["code_challenge"] and params["code_challenge_method"] not in {"", "S256"}:
            await self._redirect_error(send, params, base_url, "invalid_request")
            return

        await _send_html_response(
            send,
            200,
            render_login_page(action=f"{base_url}/authorize", hidden=self._hidden_fields(params)),
        )

    async def _handle_authorize_post(self, scope, receive, send) -> None:
        base_url = self._base_url(scope)
        form = parse_qs((await _read_body(receive)).decode("utf-8", errors="ignore"))
        params = self._authorize_params(form, base_url)

        problem = self._validate_authorize(params)
        if problem:
            await _send_text_response(send, 400, problem)
            return

        if not self.oauth.check_key(_first(form, "key")):
            await _send_html_response(
                send,
                401,
                render_login_page(
                    action=f"{base_url}/authorize",
                    hidden=self._hidden_fields(params),
                    error="Chave incorreta. Tente novamente.",
                ),
            )
            return

        code = self.oauth.issue_code(
            client_id=params["client_id"],
            redirect_uri=params["redirect_uri"],
            code_challenge=params["code_challenge"],
            resource=params["resource"],
            scope=params["scope"],
        )
        response = {"code": code, "iss": base_url}
        if params["state"]:
            response["state"] = params["state"]

        location = self.oauth.authorization_redirect(redirect_uri=params["redirect_uri"], params=response)
        await _send_text_response(send, 302, "Vínculo concluído", [(b"location", location.encode("utf-8"))])

    @staticmethod
    def _hidden_fields(params: dict) -> dict:
        return {name: params[name] for name in ("client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "scope", "resource", "response_type")}

    async def _redirect_error(self, send, params: dict, base_url: str, code: str) -> None:
        response = {"error": code, "iss": base_url}
        if params["state"]:
            response["state"] = params["state"]
        location = self.oauth.authorization_redirect(redirect_uri=params["redirect_uri"], params=response)
        await _send_text_response(send, 302, code, [(b"location", location.encode("utf-8"))])

    async def _handle_token(self, scope, receive, send) -> None:
        form = parse_qs((await _read_body(receive)).decode("utf-8", errors="ignore"))
        grant_type = _first(form, "grant_type")

        try:
            if grant_type == "authorization_code":
                payload = self.oauth.redeem_code(
                    code=_first(form, "code"),
                    code_verifier=_first(form, "code_verifier"),
                    redirect_uri=_first(form, "redirect_uri"),
                )
                tokens = self.oauth.issue_tokens(
                    audience=payload.get("aud", f"{self._base_url(scope)}{self.path_prefix}"),
                    scope=payload.get("scope", SCOPE),
                )
            elif grant_type == "refresh_token":
                tokens = self.oauth.refresh_tokens(_first(form, "refresh_token"))
            else:
                raise OAuthError("unsupported_grant_type", f"grant_type não suportado: {grant_type or '(vazio)'}")
        except OAuthError as error:
            await _send_json_response(send, error.status, error.to_dict())
            return

        await _send_json_response(send, 200, tokens)

    # ----------------------------------------------------------------- endpoint MCP

    async def _serve_mcp(self, scope, receive, send) -> None:
        base_url = self._base_url(scope)

        authorized = False
        if self.oauth.check_key(self._bridge_key_from_scope(scope)):
            authorized = True
        else:
            token = self._bearer_token(scope)
            if token and self.oauth.verify_access_token(token, self._valid_audiences(base_url)):
                authorized = True

        if not authorized:
            # Navegador sem credencial nenhuma: explica em vez de devolver 401 cru.
            if scope.get("method") in {"GET", "HEAD"} and self._is_html_request(scope):
                await _send_html_response(send, 200, INFO_PAGE)
                return

            challenge = (
                f'Bearer resource_metadata="{base_url}/.well-known/oauth-protected-resource{self.path_prefix}", '
                f'scope="{SCOPE}"'
            )
            await _send_text_response(
                send, 401, "Unauthorized", [(b"www-authenticate", challenge.encode("utf-8"))]
            )
            return

        rewritten_scope = dict(scope)
        rewritten_scope["path"] = "/"
        rewritten_scope["root_path"] = f"{scope.get('root_path', '')}{self.path_prefix}"
        await self.inner_app(rewritten_scope, receive, send)

    # --------------------------------------------------------------------- roteador

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.inner_app(scope, receive, send)
            return

        path = scope.get("path", "")
        method = scope.get("method", "")
        base_url = self._base_url(scope)

        if method == "OPTIONS":
            await _send_no_content(
                send,
                [
                    (b"access-control-allow-origin", b"*"),
                    (b"access-control-allow-methods", b"GET, POST, OPTIONS"),
                    (b"access-control-allow-headers", b"content-type, authorization, mcp-session-id, mcp-protocol-version"),
                    (b"access-control-max-age", b"86400"),
                ],
            )
            return

        if path in {"/health", "/healthz"}:
            await _send_text_response(send, 200, "ok")
            return

        if path == "/":
            await _send_text_response(send, 302, "Redirecting to /mcp", [(b"location", self.path_prefix.encode("utf-8"))])
            return

        # RFC 9728. Servido nos dois caminhos: com e sem o path do recurso.
        if path in {
            "/.well-known/oauth-protected-resource",
            f"/.well-known/oauth-protected-resource{self.path_prefix}",
        }:
            await _send_json_response(send, 200, self.oauth.protected_resource_metadata(base_url, self.path_prefix))
            return

        # RFC 8414 e OpenID Connect Discovery — a spec exige pelo menos um dos dois.
        if path in {
            "/.well-known/oauth-authorization-server",
            f"/.well-known/oauth-authorization-server{self.path_prefix}",
            "/.well-known/openid-configuration",
        }:
            await _send_json_response(send, 200, self.oauth.authorization_server_metadata(base_url))
            return

        if path == "/register" and method == "POST":
            await self._handle_register(receive, send)
            return

        if path == "/authorize":
            if method in {"GET", "HEAD"}:
                await self._handle_authorize_get(scope, send)
                return
            if method == "POST":
                await self._handle_authorize_post(scope, receive, send)
                return
            await _send_text_response(send, 405, "Method not allowed")
            return

        if path == "/token" and method == "POST":
            await self._handle_token(scope, receive, send)
            return

        if path != self.path_prefix:
            await _send_text_response(send, 404, "Not found")
            return

        await self._serve_mcp(scope, receive, send)


@asynccontextmanager
async def lifespan(server: FastMCP) -> AsyncIterator[dict]:
    app_key = os.environ["OMIE_APP_KEY"]
    app_secret = os.environ["OMIE_APP_SECRET"]
    client = OmieClient(app_key=app_key, app_secret=app_secret)
    try:
        yield {"omie": client}
    finally:
        await client.aclose()


mcp = FastMCP(
    name="omie-mcp",
    instructions=(
        "Servidor MCP para controle financeiro no ERP OMIE. "
        "Permite gerenciar: fornecedores, contas a pagar, contas a receber, "
        "lançamentos bancários, extrato de contas correntes e fluxo de caixa. "
        "Datas devem ser informadas no formato dd/mm/aaaa."
    ),
    lifespan=lifespan,
    # Configuração do transporte HTTP: o BridgeApp reescreve o path para "/"
    # antes de delegar, então o FastMCP precisa servir na raiz.
    streamable_http_path="/",
    json_response=True,
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)

# Registra todas as ferramentas financeiras
fornecedores.register(mcp)
contas_pagar.register(mcp)
contas_receber.register(mcp)
lancamentos_cc.register(mcp)
contas_correntes.register(mcp)
fluxo_caixa.register(mcp)


http_app = mcp.streamable_http_app()

app = BridgeApp(http_app, BRIDGE_KEY)


def main():
    if HTTP_MODE:
        import uvicorn

        port = int(os.getenv("PORT", "8000"))
        host = os.getenv("HOST", "0.0.0.0")
        uvicorn.run(app, host=host, port=port, log_level=os.getenv("LOG_LEVEL", "info"))
        return

    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
