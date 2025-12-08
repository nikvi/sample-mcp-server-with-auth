## Secure MCP Server & Auth Provider
This repository hosts the server-side infrastructure for a secure Model Context Protocol (MCP) environment. It provides a reference implementation of the current MCP Authorization Specification using DCR.

It consists of two independent services:
- auth_provider.py: A local OIDC Identity Provider that supports Dynamic Client Registration (DCR).
- server.py: A secure MCP Server (hosting Wikipedia tools) that enforces JWT validation

## Instructions:
1. git clone https://github.com/yourusername/mcp-server-auth.git
2. cd mcp-server-auth
3. Set up environment:
    * uv venv
    * source .venv/bin/activate 
    * uv pip install mcp fastapi uvicorn httpx pyjwt cryptography
4. **You must run both services in separate terminal windows. Order matters slightly - start the Auth Provider first so the MCP Server can fetch keys.**
5. `python auth_provider.py` - This service mimics an Identity Provider (like Auth0 or Descope) on port 9090.
6. `python server.py` - This service hosts the tools and validates tokens against the Auth Provider.
