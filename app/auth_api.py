import os
import random
import time
from datetime import datetime, timedelta
from typing import Annotated

from fastapi import Cookie, Depends, FastAPI, status
from fastapi.responses import JSONResponse
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
    OAuth2PasswordRequestForm,
)
from pytz import utc

from lib.crud import (
    create_user,
    get_reset_password,
    get_roles_from_user_id,
    get_user_from_email,
    get_user_from_username,
    insert_reset_password,
    set_last_logged_in,
    update_user_password,
)
from lib.helper import (
    ResetPasswordRequest,
    RoleCache,
    SignupRequest,
    UpdatePasswordRequest,
    check_token_validity,
    create_token,
    decode_token,
    get_hashed_password,
    send_email,
    verify_password,
)

auth_app = FastAPI()
ACCESS_TOKEN_EXPIRY_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRY_MINUTES"))
REFRESH_TOKEN_EXPIRY_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRY_DAYS"))


@auth_app.exception_handler(Exception)
async def custom_exception_handler(request, exception):
    if hasattr(exception, "status_code"):
        status_code = exception.status_code
    else:
        status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return JSONResponse(status_code=status_code, content={"message": str(exception)})


@auth_app.post(
    "/login",
    summary="Enables users to log in to the application",
    tags=["Authentication"],
)
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
):
    user = await get_user_from_username(username=form_data.username)
    roles = await get_roles_from_user_id(user_id=user.id)
    if user is None:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid credentials"},
        )
    if not verify_password(password=form_data.password, hashed_password=user.password):
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Incorrect password"},
        )

    role_names = [role.name for role in roles]
    access_token = create_token(
        data={"username": form_data.username, "role": role_names},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRY_MINUTES),
    )
    refresh_token = create_token(
        data={"username": form_data.username, "role": role_names},
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRY_DAYS),
    )
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRY_DAYS)
    response = JSONResponse(content={"access_token": access_token})
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        path="/auth/refresh-token",
        httponly=True,
        secure=True,
        samesite="Strict",
        expires=expire.strftime("%a, %d-%b-%Y %H:%M:%S GMT"),
    )
    await set_last_logged_in(username=user.username, last_logged_in=datetime.now())
    return response


@auth_app.post(
    "/signup",
    summary="Create new user for the application",
    tags=["Authentication"],
)
async def signup(
    signup_request: SignupRequest,
):
    user = await get_user_from_username(username=signup_request.username)
    if user is not None:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "User with this username already exists"},
        )

    hashed_password = get_hashed_password(password=signup_request.password)
    await create_user(
        name=signup_request.name,
        username=signup_request.username,
        email=signup_request.email,
        password=hashed_password,
        role_id=RoleCache.get_role_id("Annotator"),
    )
    return JSONResponse(
        content={"detail": "User has successfully signed up"},
    )


@auth_app.get(
    "/refresh-token",
    summary="Create new access token for the application",
    tags=["Authentication"],
)
def refresh_token(refresh_token: str = Cookie(None)):
    if not refresh_token:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Missing refresh token in the cookie"},
        )

    username, role = decode_token(refresh_token)
    access_token = create_token(
        data={"username": username, "role": role},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRY_MINUTES),
    )
    response = JSONResponse(content={"access_token": access_token})
    return response


@auth_app.post(
    "/valid-token",
    summary="Check the validity of the token",
    tags=["Authentication"],
)
def valid_token(authorization: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    if not authorization:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Missing authorization header"},
        )
    scheme = authorization.scheme
    token = authorization.credentials
    if scheme.lower() != "bearer":
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Invalid authorization scheme"},
        )
    try:
        if not check_token_validity(token):
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"message": "Token expired"},
            )
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"message": "Token expired"},
        )
    return JSONResponse(content={"detail": "Given token is valid"})


@auth_app.post(
    "/reset-password",
    summary="Reset user password",
    tags=["Authentication"],
)
async def reset_password(reset_password_request: ResetPasswordRequest):
    email = reset_password_request.email
    user = await get_user_from_email(email=email)
    if user is None:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"message": "Incorrect email"},
        )

    verification_code = str(
        ((int(time.time()) * 100000) + random.randint(0, 99999)) % 1000000
    ).zfill(6)
    expiry_time = datetime.utcnow() + timedelta(minutes=15)
    reset_password = await insert_reset_password(
        user_id=user.id,
        verification_code=verification_code,
        expiry_time=expiry_time,
    )
    await send_email(
        recepient_email=email,
        recepient_name=user.name,
        reset_id=reset_password.id,
        verification_code=verification_code,
    )
    return JSONResponse(content={"detail": "Verification code sent successfully"})


@auth_app.post(
    "/update-password",
    summary="Update user password",
    tags=["Authentication"],
)
async def update_password(
    update_password_request: UpdatePasswordRequest,
):
    reset_password = await get_reset_password(
        reset_id=update_password_request.reset_id,
        verification_code=update_password_request.verification_code,
    )
    if reset_password is None:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"message": "Incorrect credentials"},
        )

    current_timestamp = datetime.utcnow().astimezone(utc)
    if current_timestamp > reset_password.expiry_time:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={
                "message": "Time has expired for the verification code. Please try again."
            },
        )

    hashed_password = get_hashed_password(password=update_password_request.new_password)
    await update_user_password(
        user_id=reset_password.user_id, new_password=hashed_password
    )
    return JSONResponse(content={"detail": "Successfully updated user password"})
