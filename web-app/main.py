import uvicorn
from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, HttpUrl
from typing import Optional, Dict
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import jwt
import secrets
import base64
import time
from urllib.parse import urlencode
import logging
from config import settings

app = FastAPI()
security = HTTPBasic()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Logging middleware so see raw HTTP requests
@app.middleware("http")
async def log_requests(request: Request, call_next):
    body = await request.body()
    
    http_request = f"""
{request.method} {request.url.path}?{request.url.query} HTTP/1.1
Host: {request.url.hostname}
"""
    
    for header, value in request.headers.items():
        http_request += f"{header}: {value}\n"
    
    if body:
        http_request += f"\n{body.decode()}"
        
    logger.info(f"\nReceived HTTP Request:\n{http_request}")
    
    response = await call_next(request)
    return response


# JWKS Configuration
class JWKSConfig:
    def __init__(self):
        try:
            with open('private_key.pem', 'rb') as f:
                private_key_data = f.read()
                self.private_key = serialization.load_pem_private_key(
                    private_key_data,
                    password=None,
                    backend=default_backend()
                )
                self.public_key = self.private_key.public_key()
        except FileNotFoundError:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
            
            with open('private_key.pem', 'wb') as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))

jwks_config = JWKSConfig()

# Store authorization codes
auth_codes: Dict[str, dict] = {}

class TokenRequest(BaseModel):
    grant_type: str
    code: str
    redirect_uri: HttpUrl

def generate_jwks():
    public_numbers = jwks_config.public_key.public_numbers()
    n = base64.urlsafe_b64encode(public_numbers.n.to_bytes(256, 'big')).rstrip(b'=')
    e = base64.urlsafe_b64encode(public_numbers.e.to_bytes(3, 'big')).rstrip(b'=')
    
    return {
        "keys": [{
            "kty": "RSA",
            "kid": "default",
            "use": "sig",
            "alg": "RS256",
            "n": n.decode('ascii'),
            "e": e.decode('ascii')
        }]
    }

def create_id_token(sub: str, aud: str, nonce: Optional[str] = None) -> str:
    now = int(time.time())
    payload = {
        "iss": settings.ISSUER,
        "sub": sub,
        "aud": aud,
        "exp": now + 3600,
        "iat": now
    }

    if nonce:
        payload["nonce"] = nonce

    private_key_pem = jwks_config.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    return jwt.encode(payload, private_key_pem, algorithm="RS256")

@app.get("/.well-known/openid-configuration")
async def openid_configuration():
    return {
        "issuer": settings.ISSUER,
        "authorization_endpoint": f"{settings.ISSUER}/auth",
        "token_endpoint": f"{settings.ISSUER}/token",
        "jwks_uri": f"{settings.ISSUER}/jwks",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat"]
    }

@app.get("/jwks")
async def jwks():
    return generate_jwks()

@app.get("/auth")
async def authorize(
    client_id: str,
    redirect_uri: str,
    response_type: str,
    scope: Optional[str] = None,
    state: Optional[str] = None,
    nonce: Optional[str] = None
):
    # Validate client and redirect URI
    client = settings.CLIENTS.get(client_id)
    
    # For testing purposes, automatically generate and return a code
    code = secrets.token_urlsafe(32)
    auth_codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "sub": settings.SUBJECT,
        "nonce": nonce
    }

    # Build redirect URL with the code
    params = {"code": code}
    if state:
        params["state"] = state
    
    redirect_uri = f"{redirect_uri}{'&' if '?' in redirect_uri else '?'}{urlencode(params)}"
    return RedirectResponse(url=redirect_uri)

@app.post("/token")
async def token(
    credentials: HTTPBasicCredentials = Depends(security),
    token_request: TokenRequest = None
):
    # Validate client credentials
    client = settings.CLIENTS.get(credentials.username)
    if not client or client["client_secret"] != credentials.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid client credentials"
        )

    # Validate grant type
    if token_request.grant_type != "authorization_code":
        raise HTTPException(status_code=400, detail="Unsupported grant type")

    code_data = auth_codes.get(token_request.code)

    # Generate ID token
    id_token = create_id_token(
        sub=code_data["sub"],
        aud=credentials.username,
        nonce=code_data.get("nonce")
    )

    return {
        "id_token": id_token,
        "token_type": "Bearer",
        "expires_in": 3600
    }

if __name__ == "__main__":
    uvicorn.run(
        app, 
        host=settings.HOST,
        port=settings.PORT,
        ssl_keyfile=settings.SSL_KEYFILE,
        ssl_certfile=settings.SSL_CERTFILE
    )
