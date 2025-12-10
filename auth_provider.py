# auth_provider.py
import uvicorn
import time
import uuid
import json
import logging
from typing import Dict
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import JSONResponse, HTMLResponse
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt # pip install pyjwt

# --- CONFIGURATION ---
PORT = 9090
ISSUER = f"http://localhost:{PORT}"
CODE_STORE: Dict[str, dict] = {} # In-memory storage for Auth Codes

# --- LOGGING SETUP ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- CRYPTO SETUP (Generate Keys on Startup) ---
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Convert to PEM for signing (Internal)
pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Convert to JWK for exposure (External)
# We do a simplified JWK generation for demo purposes
def get_public_jwks():
    numbers = public_key.public_numbers()
    return {
        "keys": [{
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kid": "local-key-1",
            "n": int_to_base64(numbers.n),
            "e": int_to_base64(numbers.e)
        }]
    }

def int_to_base64(value):
    """Helper to encode integers for JWK"""
    import base64
    val_bytes = value.to_bytes((value.bit_length() + 7) // 8, 'big')
    return base64.urlsafe_b64encode(val_bytes).decode('utf-8').rstrip('=')

app = FastAPI()

# --- OIDC DISCOVERY ENDPOINTS ---

@app.get("/.well-known/openid-configuration")
def discovery():
    """Clients hit this to find our URLs"""
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "registration_endpoint": f"{ISSUER}/register", # DCR SUPPORTED!
        "jwks_uri": f"{ISSUER}/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"]
    }

@app.get("/jwks.json")
def jwks():
    """Server hits this to get keys to validate tokens"""
    return get_public_jwks()

# --- DYNAMIC CLIENT REGISTRATION (DCR) ---

@app.post("/register")
def register(client_metadata: dict):
    """
    Accepts ANY client registration. 
    Returns a fake Client ID to make the client happy.
    """
    logger.info(f"Registered Client: {client_metadata.get('client_name')}")
    return {
        "client_id": "local_client_" + str(uuid.uuid4())[:8],
        "client_secret": "local_secret_" + str(uuid.uuid4())[:8],
        "client_id_issued_at": int(time.time()),
        "grant_types": ["authorization_code"],
        "token_endpoint_auth_method": "client_secret_post"
    }

# --- USER LOGIN FLOW ---

@app.get("/authorize", response_class=HTMLResponse)
def authorize(response_type: str, client_id: str, redirect_uri: str, scope: str = "", resource: str = None):
    """
    Simulates a Login Page. We just auto-generate a code for the user to copy.
    """
    # Create a temporary auth code
    code = "auth_code_" + str(uuid.uuid4())[:8]
    CODE_STORE[code] = {
        "client_id": client_id, 
        "scope": scope, 
        "resource": resource,
        "redirect_uri": redirect_uri
    }
    
    # In a real browser flow, we would redirect. 
    # Since your client opens a browser but expects a manual copy-paste,
    # we show a big clear success page.
    
    html_content = f"""
    <html>
        <body style="font-family: sans-serif; text-align: center; padding: 50px;">
            <h1 style="color: green;">Login Successful</h1>
            <p>You have authenticated with the Local Provider.</p>
            <hr/>
            <h3>Copy this code:</h3>
            <div style="background: #f0f0f0; padding: 20px; font-size: 24px; font-family: monospace;">
                {code}
            </div>
            <p>Paste it back into your terminal.</p>
        </body>
    </html>
    """
    return html_content

@app.post("/token")
def token(
    grant_type: str = Form(...),
    code: str = Form(...),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    resource: str = Form(None)
):
    """Exchanges the Code for a JWT"""
    stored_data = CODE_STORE.get(code)
    
    if not stored_data:
        raise HTTPException(400, "Invalid or expired code")
    
    # Generate the JWT
    payload = {
        "iss": ISSUER,
        "sub": "user_123", # The 'User'
        "aud": resource or "http://localhost:8000", # Audience validation
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "scope": stored_data["scope"]
    }
    
    access_token = jwt.encode(payload, pem_private, algorithm="RS256", headers={"kid": "local-key-1"})
    
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600
    }

if __name__ == "__main__":
    logger.info(f"Local Auth Server running on {ISSUER}")
    uvicorn.run(app, host="0.0.0.0", port=PORT)
