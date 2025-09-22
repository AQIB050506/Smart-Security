"""
Authentication routes for user registration and login.
"""
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User
from app.schemas import UserCreate, UserLogin, UserResponse, Token
from app.auth import (
    get_password_hash, 
    authenticate_user, 
    create_access_token, 
    get_current_active_user,
    create_anonymous_user
)
from app.config import settings

router = APIRouter(prefix="/auth", tags=["authentication"])
security = HTTPBearer()


@router.post("/signup", response_model=UserResponse)
async def signup(user_data: UserCreate, db: Session = Depends(get_db)):
    """
    Register a new user.
    
    Args:
        user_data: User registration data
        db: Database session
        
    Returns:
        UserResponse with user details
    """
    # Check if user already exists
    if user_data.email:
        existing_user = db.query(User).filter(User.email == user_data.email).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
    
    # Create new user
    user = User(
        email=user_data.email,
        password_hash=get_password_hash(user_data.password) if user_data.password else None
    )
    
    db.add(user)
    db.commit()
    db.refresh(user)
    
    return user


@router.post("/login", response_model=Token)
async def login(user_credentials: UserLogin, db: Session = Depends(get_db)):
    """
    Authenticate user and return JWT token.
    
    Args:
        user_credentials: User login credentials
        db: Database session
        
    Returns:
        Token with access token and type
    """
    user = authenticate_user(db, user_credentials.email, user_credentials.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": str(user.id)}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/anonymous", response_model=Token)
async def create_anonymous_user(db: Session = Depends(get_db)):
    """
    Create an anonymous user for reporting without registration.
    
    Args:
        db: Database session
        
    Returns:
        Token with access token and type
    """
    user = create_anonymous_user(db)
    
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": str(user.id)}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_active_user)):
    """
    Get current user information.
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        UserResponse with user details
    """
    return current_user


@router.post("/logout")
async def logout():
    """
    Logout user (client-side token removal).
    
    Returns:
        Success message
    """
    return {"message": "Successfully logged out"}

