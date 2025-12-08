import uvicorn
import httpx
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
        print("⚠️ No Credentials provided.")
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
        print(f"❌ Validation Error: {e}")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid Token", headers=challenge_headers)


# --- 3. ROUTES (ASGI-level handlers) ---
from starlette.responses import JSONResponse

async def handle_sse_asgi(scope, receive, send):
    from starlette.requests import Request as StarletteRequest
    request = StarletteRequest(scope, receive, send)

    # Manual auth check with direct ASGI response
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        response = JSONResponse(
            {"detail": "Auth required"},
            status_code=401,
            headers={"WWW-Authenticate": f'Bearer realm="mcp", resource_metadata="{MCP_SERVER_URI}/.well-known/oauth-protected-resource"'}
        )
        await response(scope, receive, send)
        return

    try:
        token = auth_header.split(" ")[1]
        unverified_header = jwt.get_unverified_header(token)
        target_kid = unverified_header.get("kid")

        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{AUTH_SERVER_URI}/jwks.json")
            if resp.status_code != 200:
                raise Exception("Auth Server unreachable")
            jwks_data = resp.json()

        public_key = None
        for key_data in jwks_data["keys"]:
            if key_data["kid"] == target_kid:
                public_key = RSAAlgorithm.from_jwk(json.dumps(key_data))
                break

        if not public_key:
            raise Exception("Key not found")

        jwt.decode(token, public_key, algorithms=["RS256"], audience=MCP_SERVER_URI, issuer=AUTH_SERVER_URI)

    except Exception as e:
        print(f"❌ Validation Error: {e}")
        response = JSONResponse(
            {"detail": "Invalid Token"},
            status_code=401,
            headers={"WWW-Authenticate": f'Bearer realm="mcp", resource_metadata="{MCP_SERVER_URI}/.well-known/oauth-protected-resource"'}
        )
        await response(scope, receive, send)
        return

    # Auth passed - hand over to MCP
    async with sse.connect_sse(scope, receive, send) as streams:
        await mcp.run(streams[0], streams[1], mcp.create_initialization_options())

async def handle_messages_asgi(scope, receive, send):
    from starlette.requests import Request as StarletteRequest
    request = StarletteRequest(scope, receive, send)

    auth_header = request.headers.get("Authorization")
    if not auth_header:
        response = JSONResponse(
            {"detail": "Auth required"},
            status_code=401,
            headers={"WWW-Authenticate": f'Bearer realm="mcp", resource_metadata="{MCP_SERVER_URI}/.well-known/oauth-protected-resource"'}
        )
        await response(scope, receive, send)
        return

    try:
        token = auth_header.split(" ")[1]
        unverified_header = jwt.get_unverified_header(token)
        target_kid = unverified_header.get("kid")

        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{AUTH_SERVER_URI}/jwks.json")
            if resp.status_code != 200:
                raise Exception("Auth Server unreachable")
            jwks_data = resp.json()

        public_key = None
        for key_data in jwks_data["keys"]:
            if key_data["kid"] == target_kid:
                public_key = RSAAlgorithm.from_jwk(json.dumps(key_data))
                break

        if not public_key:
            raise Exception("Key not found")

        jwt.decode(token, public_key, algorithms=["RS256"], audience=MCP_SERVER_URI, issuer=AUTH_SERVER_URI)

    except Exception as e:
        print(f"❌ Validation Error: {e}")
        response = JSONResponse(
            {"detail": "Invalid Token"},
            status_code=401,
            headers={"WWW-Authenticate": f'Bearer realm="mcp", resource_metadata="{MCP_SERVER_URI}/.well-known/oauth-protected-resource"'}
        )
        await response(scope, receive, send)
        return

    # Auth passed - hand over to MCP
    await sse.handle_post_message(scope, receive, send)

# Mount as raw ASGI to avoid FastAPI's response handling
from starlette.routing import Mount, Route

# Wrap ASGI handlers to match Starlette's expectations
class ASGIApp:
    def __init__(self, handler):
        self.handler = handler

    async def __call__(self, scope, receive, send):
        await self.handler(scope, receive, send)

app.router.routes.insert(0, Route("/sse", ASGIApp(handle_sse_asgi), methods=["GET"]))
app.router.routes.insert(0, Route("/messages", ASGIApp(handle_messages_asgi), methods=["POST"]))


# --- TOOLS (Unchanged) ---
async def fetch_wikipedia_summary(query: str) -> str:
    async with httpx.AsyncClient() as client:
        # Search
        search = (await client.get(WIKIPEDIA_API_URL, params={
            "action": "query", "format": "json", "list": "search", "srsearch": query, "srlimit": 1
        })).json()
        
        if not search.get("query", {}).get("search"):
            return "No results found."
        
        title = search["query"]["search"][0]["title"]
        
        # Content
        content = (await client.get(WIKIPEDIA_API_URL, params={
            "action": "query", "format": "json", "prop": "extracts", 
            "exintro": True, "explaintext": True, "titles": title
        })).json()
        
        page_id = next(iter(content["query"]["pages"]))
        return f"--- {title} ---\n{content['query']['pages'][page_id]['extract']}"

@mcp.list_tools()
async def list_tools():
    return [Tool(name="search_wikipedia", description="Search Wikipedia", inputSchema={"type":"object", "properties":{"query":{"type":"string"}}, "required": ["query"]})]

@mcp.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "search_wikipedia":
        return [TextContent(type="text", text=await fetch_wikipedia_summary(arguments["query"]))]
    raise ValueError(f"Tool {name} not found")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)