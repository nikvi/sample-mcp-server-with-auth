import uvicorn
import httpx
import logging
import jwt
import json
from typing import Optional
from fastapi import FastAPI, Request, HTTPException, status, Depends
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import Tool, TextContent
from jwt.algorithms import RSAAlgorithm

# --- CONFIGURATION ---
MCP_SERVER_URI = "http://localhost:8000"
AUTH_SERVER_URI = "http://localhost:9090"
WIKIPEDIA_API_URL = "https://en.wikipedia.org/w/api.php"
WIKI_HEADERS = {
    'User-Agent': 'SecureMCPServer/1.0 (https://github.com/nikvi/sample-mcp-server-with-auth)'
}

# --- LOGGING SETUP ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("MCP_Server")

app = FastAPI()
mcp = Server("secure-wikipedia-mcp")
sse = SseServerTransport("/messages")

# --- 1. METADATA ENDPOINT ---
@app.get("/.well-known/oauth-protected-resource")
async def resource_metadata():
    return {
        "resource": MCP_SERVER_URI,
        "authorization_servers": [AUTH_SERVER_URI],
        "scopes_supported": ["mcp_tool_use"]
    }

# --- 2. AUTH LOGIC (Split for reuse) ---
async def validate_request_auth(request: Request):
    """
    Manual Auth Check that allows the route to handle the response lifecycle.
    """
    challenge_headers = {
        "WWW-Authenticate": f'Bearer realm="mcp", resource_metadata="{MCP_SERVER_URI}/.well-known/oauth-protected-resource"'
    }

    auth_header = request.headers.get("Authorization")
    if not auth_header:
        logger.warning("No Credentials provided.")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Auth required", headers=challenge_headers)

    try:
        token = auth_header.split(" ")[1]
        
        # A: Get Key ID
        unverified_header = jwt.get_unverified_header(token)
        target_kid = unverified_header.get("kid")

        # B: Fetch JWKS
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{AUTH_SERVER_URI}/jwks.json")
            if resp.status_code != 200:
                raise Exception("Auth Server unreachable")
            jwks_data = resp.json()

        # C: Find Key
        public_key = None
        for key_data in jwks_data["keys"]:
            if key_data["kid"] == target_kid:
                public_key = RSAAlgorithm.from_jwk(json.dumps(key_data))
                break
        
        if not public_key:
            raise Exception("Key not found")

        # D: Validate
        jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=MCP_SERVER_URI,
            issuer=AUTH_SERVER_URI
        )
        # Auth Success - No return needed, we just don't raise
        return

    except Exception as e:
        logger.error(f"Validation Error: {e}", exc_info=True)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid Token", headers=challenge_headers)


# --- 3. ROUTES (ASGI-level handlers) ---
from starlette.responses import JSONResponse

async def handle_sse_asgi(scope, receive, send):
    from starlette.requests import Request as StarletteRequest
    request = StarletteRequest(scope, receive, send)

    try:
        await validate_request_auth(request)
        # Auth passed - hand over to MCP
        async with sse.connect_sse(scope, receive, send) as streams:
            await mcp.run(streams[0], streams[1], mcp.create_initialization_options())
    except HTTPException as e:
        response = JSONResponse(content={"detail": e.detail}, status_code=e.status_code, headers=e.headers)
        await response(scope, receive, send)

async def handle_messages_asgi(scope, receive, send):
    from starlette.requests import Request as StarletteRequest
    request = StarletteRequest(scope, receive, send)
    try:
        await validate_request_auth(request)
        # Auth passed - hand over to MCP
        await sse.handle_post_message(scope, receive, send)
    except HTTPException as e:
        response = JSONResponse(content={"detail": e.detail}, status_code=e.status_code, headers=e.headers)
        await response(scope, receive, send)

# --- TOOL IMPLEMENTATIONS ---

async def check_wiki_connectivity() -> str:
    """Performs a simple API call to check Wikipedia connectivity."""
    try:
        async with httpx.AsyncClient(headers=WIKI_HEADERS, timeout=10.0) as client:
            response = await client.get(
                WIKIPEDIA_API_URL,
                params={"action": "query", "meta": "siteinfo", "format": "json"}
            )
            response.raise_for_status()  # Raises HTTPStatusError for 4xx/5xx responses
            if "query" in response.json():
                return "Successfully connected to the Wikipedia API."
            return "Connection to Wikipedia API was successful, but the response was unexpected."
    except httpx.RequestError as exc:
        logger.error(f"Wikipedia connectivity check failed: {exc}")
        return f"Failed to connect to Wikipedia API. Error: {exc.__class__.__name__}"

async def fetch_wikipedia_summary(query: str) -> str:
    try:
        async with httpx.AsyncClient(headers=WIKI_HEADERS) as client:
            # Search
            search_response = await client.get(WIKIPEDIA_API_URL, params={
                "action": "query", "format": "json", "list": "search", "srsearch": query, "srlimit": 1
            })
            search_response.raise_for_status()
            search = search_response.json()

            if not search.get("query", {}).get("search"):
                return "No results found."

            title = search["query"]["search"][0]["title"]

            # Content
            content_response = await client.get(WIKIPEDIA_API_URL, params={
                "action": "query", "format": "json", "prop": "extracts",
                "exintro": True, "explaintext": True, "titles": title
            })
            content_response.raise_for_status()
            content = content_response.json()

            page_id = next(iter(content["query"]["pages"]))
            return f"--- {title} ---\n{content['query']['pages'][page_id]['extract']}"
    except httpx.RequestError as exc:
        logger.error(f"Wikipedia search failed for query '{query}': {exc}")
        return f"Failed to connect to Wikipedia API. Error: {exc.__class__.__name__}"

@mcp.list_tools()
async def list_tools():
    return [
        Tool(
            name="search_wikipedia",
            description="Search Wikipedia for a query and return a summary of the top result.",
            inputSchema={"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}
        ),
        Tool(
            name="check_wikipedia_connectivity",
            description="Checks if the server can successfully connect to the Wikipedia API.",
            inputSchema={"type": "object", "properties": {}}
        )
    ]

@mcp.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "search_wikipedia":
        return [TextContent(type="text", text=await fetch_wikipedia_summary(arguments["query"]))]
    elif name == "check_wikipedia_connectivity":
        return [TextContent(type="text", text=await check_wiki_connectivity())]
    raise ValueError(f"Tool {name} not found")

# Mount as raw ASGI to avoid FastAPI's response handling
from starlette.routing import Route

# Wrap ASGI handlers to match Starlette's expectations
class ASGIApp:
    def __init__(self, handler):
        self.handler = handler

    async def __call__(self, scope, receive, send):
        await self.handler(scope, receive, send)

app.router.routes.insert(0, Route("/messages", ASGIApp(handle_messages_asgi), methods=["POST"]))
app.router.routes.insert(0, Route("/sse", ASGIApp(handle_sse_asgi), methods=["GET"]))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)