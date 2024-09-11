from typing import Annotated, List

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, status
from fastapi.datastructures import UploadFile
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer

from lib.crud import (
    create_dataset,
    get_datasets,
    get_user_from_username,
    get_user_roles,
    update_user_roles,
)
from lib.helper import (
    Dataset,
    DatasetRequest,
    DocumentParser,
    RoleCache,
    User,
    UserRoleUpdate,
    decode_token,
)

jwt_http_bearer = HTTPBearer()


def enforce_admin_role(jwt_token: Annotated[str, Depends(jwt_http_bearer)]):
    _, role = decode_token(jwt_token.credentials)
    if role is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Role not found in token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not any(allowed_role in role for allowed_role in ["Admin"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have the necessary permissions",
        )


protected_router = APIRouter(dependencies=[Depends(enforce_admin_role)])
unprotected_router = APIRouter()
admin_app = FastAPI()


@admin_app.exception_handler(Exception)
async def custom_exception_handler(request, exception):
    if hasattr(exception, "status_code"):
        status_code = exception.status_code
    else:
        status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return JSONResponse(status_code=status_code, content={"message": str(exception)})


@protected_router.get(
    "/all-roles",
    summary="Get all roles with role_id",
    tags=["roles"],
)
async def get_all_roles() -> list[dict]:
    return RoleCache.roles


@protected_router.get(
    "/user-roles",
    summary="Get all users with role_id",
    tags=["roles"],
)
async def fetch_user_roles():
    user_role_mapping = await get_user_roles()
    users = {}
    for user, role_id in user_role_mapping:
        user_id = str(user.id)
        if user_id not in users:
            users[user_id] = {
                "id": user_id,
                "name": user.name,
                "username": user.username,
                "email": user.email,
                "roles": [],
            }
        users[user_id]["roles"].append(str(role_id))

    return [User(**user) for user in users.values()]


@protected_router.put(
    "/user-roles",
    summary="Update the users with roles",
    tags=["roles"],
)
async def put_user_roles(user_roles: List[UserRoleUpdate]):
    user_roles = [
        {"user_id": user_role.user_id, "role_id": user_role.role_id}
        for user_role in user_roles
    ]
    await update_user_roles(user_roles=user_roles)
    return JSONResponse(
        content={"detail": "User role updation is successful"},
    )


@protected_router.get(
    "/datasets",
    summary="Get all datasets",
    tags=["datasets"],
)
async def get_all_datasets():
    datasets_with_username = await get_datasets()
    datasets = []
    for dataset, username in datasets_with_username:
        datasets.append(
            Dataset(
                id=str(dataset.id),
                name=dataset.name,
                description=dataset.description,
                status=dataset.status,
                created_by=username,
            )
        )
    return datasets


@protected_router.post(
    "/datasets",
    summary="Upload a dataset",
    tags=["datasets"],
)
async def post_dataset(
    request: Request,
    dataset_request: DatasetRequest,
    files: List[UploadFile],
    document_parser: Annotated[DocumentParser, Depends(DocumentParser)],
):
    _, token = request.headers.get("authorization").split()
    user_name, _ = decode_token(token=token)
    user = await get_user_from_username(username=user_name)
    documents = []
    for file in files:
        parsed_content = document_parser.parse_file(file)
        documents.append({"file_name": file.filename, "content": parsed_content})
    await create_dataset(
        name=dataset_request.name,
        description=dataset_request.description,
        created_by=user.id,
        documents_list=documents,
    )
    return JSONResponse(
        content={"detail": "Dataset upload is successful"},
    )


admin_app.include_router(protected_router)
admin_app.include_router(unprotected_router)
