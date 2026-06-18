from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.user import User
from app.schemas.user import UserCreate, UserLogin, UserResponse, Token, RefreshRequest
from app.utils.auth import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_user_id,
)
from app.config import settings

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(body: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == body.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    if db.query(User).filter(User.username == body.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")

    user = User(
        email=body.email,
        username=body.username,
        hashed_password=hash_password(body.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=Token)
def login(body: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email).first()
    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")

    payload = {"sub": str(user.id)}
    return Token(
        access_token=create_access_token(payload, settings.secret_key, settings.access_token_expire_minutes),
        refresh_token=create_refresh_token(payload, settings.secret_key, settings.refresh_token_expire_days),
    )


@router.post("/refresh", response_model=Token)
def refresh(body: RefreshRequest):
    token_data = decode_token(body.refresh_token, settings.secret_key)
    if token_data is None:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    payload = {"sub": str(token_data.user_id)}
    return Token(
        access_token=create_access_token(payload, settings.secret_key, settings.access_token_expire_minutes),
        refresh_token=create_refresh_token(payload, settings.secret_key, settings.refresh_token_expire_days),
    )


@router.get("/me", response_model=UserResponse)
def get_me(user_id: int = Depends(get_current_user_id), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user
