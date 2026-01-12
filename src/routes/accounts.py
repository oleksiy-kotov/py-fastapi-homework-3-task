from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, status, HTTPException
from jose import JWTError

from sqlalchemy import select, delete

from sqlalchemy.ext.asyncio import AsyncSession

from schemas import TokenRefreshResponseSchema

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)

from schemas.accounts import (UserRegistrationRequestSchema,
                              UserRegistrationResponseSchema,
                              UserActivationRequestSchema,
                              PasswordResetRequestSchema,
                              PasswordResetCompleteRequestSchema,
                              UserLoginResponseSchema,
                              UserLoginRequestSchema,
                              TokenRefreshRequestSchema,
                              MessageResponseSchema)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password, verify_password
from security.utils import generate_secure_token

router = APIRouter(prefix="/accounts", tags=["accounts"])


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register_user(user_data: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    query = select(UserModel).where(UserModel.email == user_data.email)
    result = await db.execute(query)
    user = result.scalar_one_or_none()
    if user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail=f"A user with this email {user_data.email} already exists.")
    password_hashed = hash_password(user_data.password)
    new_user = UserModel(
        email=user_data.email,
        password=password_hashed,
    )
    try:
        async with db.begin():
            db.add(new_user)
            await db.flush()
            token = generate_secure_token()
            activation = (ActivationTokenModel(user_id=new_user.id,
                                               token=token,
                                               expires_at=datetime.utcnow() + timedelta(hours=24)))
            db.add(activation)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )

    return UserRegistrationResponseSchema(id=new_user.id, email=new_user.email)


@router.post("/activate/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
async def activate_user(request_data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).where(UserModel.email == request_data.email))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User does not exist.")
    if user.is_active:
        raise HTTPException(status_code=status.HTTP_200_OK, detail="User account is already active.")
    result = await db.execute(
        select(ActivationTokenModel).where(
            ActivationTokenModel.user_id == user.id,
            ActivationTokenModel.token == request_data.token,
            ActivationTokenModel.expires_at > datetime.utcnow()
        )
    )
    token = result.scalar_one_or_none()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )
    try:
        async with db.begin():
            user.is_active = True
            db.delete(token)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to activate user."
        )
    return {"message": "User account activated successfully."}


@router.post("/password_reset/request/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
async def request_password_reset(
        payload: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(UserModel).where(UserModel.email == payload.email)
    )
    user = result.scalar_one_or_none()

    if user and user.is_active:
        await db.execute(
            delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
        )
        reset_token = generate_secure_token()
        new_token = PasswordResetTokenModel(
            user_id=user.id,
            token=reset_token,
            expires_at=datetime.utcnow() + timedelta(hours=24)
        )
        db.add(new_token)
        await db.commit()

        # TODO: send password reset email to payload.email with reset_token

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/password_reset/complete/",
             response_model=MessageResponseSchema,
             status_code=status.HTTP_200_OK)
async def response_password_reset_complete(
        payload: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid email or token."
    )
    result = await db.execute(select(UserModel).where(UserModel.email == payload.email))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise credentials_exception
    result = await db.execute(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id,
            PasswordResetTokenModel.token == payload.token
        )
    )
    token = result.scalar_one_or_none()
    if not token or token.expires_at < datetime.utcnow():
        if token:
            await db.delete(token)
            await db.commit()
        raise credentials_exception
    try:
        async with db.begin():
            user.password = hash_password(payload.password)
            await db.delete(token)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )
    return {"message": "Password reset successfully."}


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_200_OK)
async def login(
        form_data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
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

    access_token = jwt_manager.create_access_token(
        data={"sub": user.email},
        expires_delta=timedelta(minutes=get_settings().ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    try:

        refresh_token = jwt_manager.create_refresh_token(user=user)
        refresh_token_obj = RefreshTokenModel(
            user_id=user.id,
            token=refresh_token,
            expires_at=datetime.utcnow() + timedelta(hours=24)
        )
        db.add(refresh_token_obj)
        await db.commit()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


@router.post("/refresh/", response_model=TokenRefreshResponseSchema, status_code=status.HTTP_200_OK)
async def refresh_access_token(
        request_data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired refresh token",
    )

    result = await db.execute(select(RefreshTokenModel).where(RefreshTokenModel.token == request_data.refresh_token))
    token_record = result.scalar_one_or_none()

    if not token_record:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found.")

    if token_record.expires_at < datetime.now(timezone.utc):
        await db.delete(token_record)
        await db.commit()
        raise credentials_exception
    try:
        payload = jwt_manager.decode_refresh_token(request_data.refresh_token)
        user_id = payload.get("sub")
        if not user_id:
            raise credentials_exception
    except JWTError:
        await db.delete(token_record)
        await db.commit()
        raise credentials_exception

    result = await db.execute(select(UserModel).where(UserModel.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    if not user.is_active:
        await db.delete(token_record)
        await db.commit()
        raise credentials_exception

    try:
        async with db.begin():
            await db.delete(token_record)
            access_token = jwt_manager.create_access_token(
                data={"sub": user.id},
                expires_delta=timedelta(minutes=get_settings().ACCESS_TOKEN_EXPIRE_MINUTES)
            )
            refresh_token = jwt_manager.create_refresh_token(user=user)
            db.add(
                RefreshTokenModel(
                    token=refresh_token,
                    user_id=user.id,
                    expires_at=datetime.now(timezone.utc) + timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
                )
            )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while refreshing the token."
        )
    return TokenRefreshResponseSchema(
        access_token=access_token,
    )
