"""MCP Server para integração com o OMIE ERP."""

import os
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from urllib.parse import parse_qs

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from dotenv import load_dotenv

from .client import OmieClient
from .tools import fornecedores, contas_pagar, contas_receber, lancamentos_cc, contas_correntes, fluxo_caixa

# Busca .env no diretório atual e em ~/.config/omie-mcp/ (útil para uso via uvx)
load_dotenv()
load_dotenv(os.path.expanduser("~/.config/omie-mcp/.env"))

BRIDGE_PATH = "/mcp"
BRIDGE_KEY = os.getenv("MCP_BRIDGE_KEY", "omie-mcp-bridge-2026")
HTTP_MODE = os.getenv("MCP_TRANSPORT", "").lower() in {"http", "streamable-http", "web"} or bool(os.getenv("PORT"))
HTML_PAGE = """<!doctype html>
<html lang="pt-BR">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>omie-mcp bridge</title>
    <style>
        :root { color-scheme: light; --bg: #0b1220; --panel: #111a2e; --text: #e5eefb; --muted: #92a4c3; --accent: #7cc4ff; }
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
        input {
            width: 100%; border: 1px solid rgba(146, 164, 195, 0.35); border-radius: 12px;
            background: #0b1020; color: var(--text); padding: 14px 16px; font-size: 16px;
            outline: none;
        }
        input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(124, 196, 255, 0.15); }
        button {
            margin-top: 16px; width: 100%; border: 0; border-radius: 12px; padding: 14px 16px;
            background: linear-gradient(135deg, #7cc4ff, #4f8cff); color: #07111f;
            font-weight: 700; font-size: 16px; cursor: pointer;
        }
        .hint { margin-top: 18px; font-size: 13px; color: var(--muted); word-break: break-all; }
        code { color: #b9dcff; }
        .status { margin-top: 14px; min-height: 1.4em; color: #ffd47c; }
    </style>
</head>
<body>
    <main class="card">
        <h1>omie-mcp bridge</h1>
        <p>Digite a chave para liberar o acesso ao bridge. Depois disso, copie a URL gerada e use-a no Claude.</p>
        <form id="bridge-form" method="post" action="/mcp">
            <label for="key">Chave</label>
            <input id="key" name="key" type="password" placeholder="Digite a chave do bridge" autocomplete="off" autofocus>
            <button type="submit">Acessar bridge</button>
        </form>
        <div class="status" id="status"></div>
        <div class="hint" id="bridge-url" hidden></div>
    </main>
    <script>
        const form = document.getElementById('bridge-form');
        const keyInput = document.getElementById('key');
        const status = document.getElementById('status');
        const bridgeUrl = document.getElementById('bridge-url');

        form.addEventListener('submit', (event) => {
            const key = keyInput.value.trim();
            if (!key) {
                event.preventDefault();
                status.textContent = 'Informe a chave para continuar.';
                bridgeUrl.hidden = true;
                return;
            }

            if (window.location.protocol === 'https:') {
                const target = new URL(window.location.href);
                target.searchParams.set('key', key);
                bridgeUrl.hidden = false;
                bridgeUrl.innerHTML = 'URL liberada: <code>' + target.toString() + '</code>';
                status.textContent = 'Se o Claude pedir, use esta URL liberada.';
            }
        });
    </script>
</body>
</html>"""


async def _send_text_response(send, status_code: int, text: str, extra_headers: list[tuple[bytes, bytes]] | None = None) -> None:
    body = text.encode("utf-8")
    headers = [
        (b"content-type", b"text/plain; charset=utf-8"),
        (b"content-length", str(len(body)).encode("ascii")),
    ]
    if extra_headers:
        headers.extend(extra_headers)
    await send({"type": "http.response.start", "status": status_code, "headers": headers})
    await send({"type": "http.response.body", "body": body})


class KeyedBridgeApp:
    def __init__(self, inner_app, api_key: str, path_prefix: str = BRIDGE_PATH) -> None:
        self.inner_app = inner_app
        self.api_key = api_key.strip("/")
        self.path_prefix = path_prefix.rstrip("/")

    @staticmethod
    def _header(scope, header_name: bytes) -> str:
        for raw_name, raw_value in scope.get("headers", []):
            if raw_name.lower() == header_name:
                return raw_value.decode("utf-8", errors="ignore")
        return ""

    def _is_html_request(self, scope) -> bool:
        accept = self._header(scope, b"accept").lower()
        return "text/html" in accept and "application/json" not in accept and "text/event-stream" not in accept

    def _bridge_key_from_scope(self, scope) -> str:
        query_string = scope.get("query_string", b"").decode("utf-8", errors="ignore")
        query_params = parse_qs(query_string)
        if query_params.get("key"):
            return query_params["key"][0]

        header_key = self._header(scope, b"x-bridge-key")
        if header_key:
            return header_key

        return ""

    async def _handle_bridge_login(self, scope, receive, send) -> None:
        body = b""
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] != "http.request":
                continue
            body += message.get("body", b"")
            more_body = message.get("more_body", False)

        form_data = parse_qs(body.decode("utf-8", errors="ignore"))
        provided_key = form_data.get("key", [""])[0]

        if provided_key != self.api_key:
            await _send_text_response(send, 401, "Invalid bridge key")
            return

        redirect_to = f"{self.path_prefix}?key={self.api_key}"
        await _send_text_response(send, 302, "Bridge liberado", [(b"location", redirect_to.encode("utf-8"))])

    async def _serve_landing_page(self, send) -> None:
        body = HTML_PAGE.encode("utf-8")
        headers = [
            (b"content-type", b"text/html; charset=utf-8"),
            (b"content-length", str(len(body)).encode("ascii")),
            (b"cache-control", b"no-store"),
        ]
        await send({"type": "http.response.start", "status": 200, "headers": headers})
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.inner_app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path in {"/health", "/healthz"}:
            await _send_text_response(send, 200, "ok")
            return

        if path == "/":
            await _send_text_response(send, 302, "Redirecting to /mcp", [(b"location", b"/mcp")])
            return

        if path != self.path_prefix:
            await _send_text_response(send, 404, "Not found")
            return

        method = scope.get("method", "")

        # Navegador pedindo a tela de vínculo. Só GET/HEAD: um cliente MCP fala por
        # POST e nunca manda Accept: text/html, então não cai aqui.
        if method in {"GET", "HEAD"} and self._is_html_request(scope):
            await self._serve_landing_page(send)
            return

        # Submissão do formulário HTML. Precisa checar o content-type: sem isso este
        # branch engole os POSTs JSON-RPC do protocolo MCP e devolve 401 em todos.
        if method == "POST" and "application/x-www-form-urlencoded" in self._header(scope, b"content-type").lower():
            await self._handle_bridge_login(scope, receive, send)
            return

        provided_key = self._bridge_key_from_scope(scope)
        if provided_key != self.api_key:
            if self._is_html_request(scope):
                await self._serve_landing_page(send)
            else:
                await _send_text_response(send, 401, "Invalid bridge key")
            return

        rewritten_scope = dict(scope)
        rewritten_scope["path"] = "/"
        rewritten_scope["root_path"] = f"{scope.get('root_path', '')}{self.path_prefix}"
        await self.inner_app(rewritten_scope, receive, send)


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
    # Configuração do transporte HTTP: o KeyedBridgeApp reescreve o path para "/"
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

app = KeyedBridgeApp(http_app, BRIDGE_KEY)


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
