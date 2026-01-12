from datetime import datetime, timezone, timedelta
from http.client import responses
from typing import cast, Optional

from fastapi import APIRouter, Depends, status, HTTPException, logger
from jose import jwt, JWTError
from pip._internal import req
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from schemas import TokenRefreshResponseSchema
from security.token_manager import JWTAuthManager
from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from schemas.accounts import UserRegistrationRequestSchema, UserRegistrationResponseSchema, UserActivationRequestSchema, \
    PasswordResetRequestSchema, PasswordResetCompleteRequestSchema, UserLoginResponseSchema, UserLoginRequestSchema, \
    TokenRefreshRequestSchema, MessageResponseSchema
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password, verify_password

router = APIRouter()


@router.post("/register", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register_user(user_data: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    try:
        created_user = await create_user(db, user_data)
        return UserRegistrationResponseSchema(
            id=created_user.id,
            email=created_user.email
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        raise HTTPException(status_code=500,
                            detail="An error occurred during user creation.")


@router.post("/activate", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
async def activate_user(request_data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid or expired activation token.",
    )
    try:
        payload = jwt.decode(
            request_data.token,
            get_settings().SECRET_KEY,
            algorithms=[get_settings().ALGORITHM]
        )
        if payload.get("type") != "activation":
            raise credentials_exception
        email: str = payload.get("email")
        if email is None or email != request_data.email:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    result = await db.execute(select(UserModel).where(UserModel.email == request_data.email))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User does not exist.")
    if user.is_active:
        raise HTTPException(status_code=400, detail="User already activated.")
    user.is_active = True
    await db.commit()
    await db.refresh(user)
    return {"message": "User account activated successfully."}


@router.post("/password_reset/request", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
async def request_password_reset(
        payload: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(UserModel).where(UserModel.email == payload.email)
    )
    user = result.scalar_one_or_none()
    if user and user.is_active:
        reset_token = create_jwt_token(
            data={"sub": user.email, "type": "password_reset"},
            expires_delta=timedelta(hours=get_settings().RESET_TOKEN_EXPIRE_HOURS))

        await send_password_reset_email(payload.email, reset_token)
    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/password_reset/complete",
             response_model=MessageResponseSchema,
             status_code=status.HTTP_200_OK)
async def response_password_reset_complete(payload: PasswordResetCompleteRequestSchema,
                                           db: AsyncSession = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid or expired password reset token."
    )

    try:
        decoded = jwt.decode(
            payload.token,
            get_settings().SECRET_KEY,
            algorithms=[get_settings().ALGORITHM]
        )

        if decoded.get("type") != "password_reset":
            raise credentials_exception

        if decoded.get("sub") != payload.email:
            raise credentials_exception

    except JWTError:
        raise credentials_exception

    result = await db.execute(
        select(UserModel).where(UserModel.email == payload.email)
    )
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=400, detail="Invalid or expired password reset token.")

    user.password = hash_password(payload.password)
    await db.commit()
    await db.refresh(user)
    return {"message": "Password reset successfully."}


@router.post("/login", response_model=UserLoginResponseSchema, status_code=status.HTTP_200_OK)
async def login(form_data: UserLoginRequestSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).where(UserModel.email == form_data.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="User account is not activated.")

    access_token = create_access_token(
        data={"sub": user.email},
        expires_delta=timedelta(minutes=get_settings().ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    refresh_token = create_refresh_token(user=user)
    return {"access_token": access_token, "token_type": "bearer", "refresh_token": refresh_token}


@router.post("/refresh", response_model=TokenRefreshResponseSchema, status_code=status.HTTP_200_OK)
async def refresh_access_token(request_data: TokenRefreshRequestSchema, db: AsyncSession = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    result = await db.execute(select(RefreshTokenModel).where(RefreshTokenModel.token == request_data.token))
    token_record = result.scalar_one_or_none()

    if not token_record:
        raise credentials_exception

    if token_record.expires_at < datetime.now(timezone.utc):
        await db.delete(token_record)
        await db.commit()
        raise credentials_exception
    try:
        payload = jwt.decode(
            request_data.token,
            get_settings().SECRET_KEY,
            algorithms=[get_settings().ALGORITHM]
        )
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        await db.delete(token_record)
        await db.commit()
        raise credentials_exception

    user_result = await db.execute(
        select(UserModel).where(UserModel.email == email)
    )
    user = user_result.scalar_one_or_none()

    if not user or not user.is_active:
        await db.delete(token_record)
        await db.commit()
        raise credentials_exception
    try:
        await db.delete(token_record)

        access_token = create_access_token(
            data={"sub": user.email},
            expires_delta=timedelta(minutes=get_settings().ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        new_refresh_token = create_refresh_token(user=user)
        new_token_record = RefreshTokenModel(
            token=new_refresh_token.token,
            user_id=user.id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=get_settings().REFRESH_TOKEN_EXPIRE_MINUTES),
        )
        db.add(new_token_record)

        await db.commit()
    except Exception as e:
        await db.rollback()
        logger.error(f"Error refreshing token: {e}")
        raise HTTPException(500, "Error refreshing token")

    return TokenRefreshResponseSchema(
        access_token=access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
    )
