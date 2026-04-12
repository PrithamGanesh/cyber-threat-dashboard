"""Authentication endpoints (demo purpose - use proper OAuth2 in production)."""
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from app.core.security import create_access_token
import logging

router = APIRouter()
logger = logging.getLogger(__name__)

# In production, implement proper user database and password hashing
# This is DEMO ONLY - do not use in production!
DEMO_USERS = {
    "user": "password123",
    "admin": "admin123",
}


class LoginRequest(BaseModel):
    """Login request schema."""
    username: str
    password: str


class TokenResponse(BaseModel):
    """Token response schema."""
    access_token: str
    token_type: str = "bearer"


@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest) -> TokenResponse:
    """
    Get JWT access token (DEMO PURPOSE ONLY).
    
    WARNING: This is a simplified demo login. In production:
    - Use proper user database (PostgreSQL)
    - Hash passwords with bcrypt (NOT plaintext)
    - Implement proper OAuth2 or OIDC
    - Use secure password storage
    - Add rate limiting on login attempts
    
    Demo credentials:
    - username: "user" / password: "password123"
    - username: "admin" / password: "admin123"
    
    Args:
        request: Login credentials
    
    Returns:
        JWT access token
    
    Raises:
        HTTPException 401: If credentials are invalid
    """
    # Validate credentials (DEMO ONLY - never do this in production!)
    if request.username not in DEMO_USERS or DEMO_USERS[request.username] != request.password:
        logger.warning(f"Failed login attempt for user: {request.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    
    # Create JWT token
    token = create_access_token({"sub": request.username})
    logger.info(f"User {request.username} logged in successfully")
    
    return TokenResponse(access_token=token, token_type="bearer")
