import os
from typing import Annotated, List

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, status
from fastapi.datastructures import UploadFile
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer

from indexer.indexing import LangchainIndexer
from lib.crud import (
    create_dataset,
    get_annotators,
    get_datasets,
    get_documents_from_dataset_id,
    get_documents_info_from_dataset_id,
    get_unassigned_annotators_documents,
    get_user_from_username,
    get_user_roles,
    set_indexed_status_to_dataset,
    update_annotator_document_assignment,
    update_user_roles,
)
from lib.helper import (
    Dataset,
    DocumentAssignment,
    DocumentInformation,
    DocumentParser,
    IndexRequest,
    Mailer,
    QuestionAnswerList,
    RoleCache,
    User,
    UserRoleUpdate,
    decode_token,
)

from .user_api import get_question_answers

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
    tags=["Roles"],
)
async def get_all_roles() -> list[dict]:
    return RoleCache.roles


@protected_router.get(
    "/user-roles",
    summary="Get all users with role_id",
    tags=["Roles"],
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
    tags=["Roles"],
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
    tags=["Datasets"],
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
                created_at=dataset.created_at,
            )
        )
    return datasets


@protected_router.post(
    "/datasets",
    summary="Upload a dataset",
    tags=["Datasets"],
)
async def post_dataset(
    request: Request,
    dataset_name: str,
    dataset_description: str,
    files: List[UploadFile],
    document_parser: Annotated[DocumentParser, Depends(DocumentParser)],
):
    _, token = request.headers.get("authorization").split()
    user_name, _ = decode_token(token=token)
    user = await get_user_from_username(username=user_name)
    documents = []
    for file in files:
        parsed_content = document_parser.parse_file(file)
        documents.append(
            {"file_name": file.filename, "size": file.size, "content": parsed_content}
        )
    await create_dataset(
        name=dataset_name,
        description=dataset_description,
        created_by=user.id,
        documents_list=documents,
    )
    return JSONResponse(
        content={"detail": "Dataset upload is successful"},
    )


@protected_router.get(
    "/datasets/{dataset_id}",
    summary="Get a dataset with dataset-id",
    tags=["Datasets"],
)
async def get_dataset_from_id(dataset_id: str):
    documents = await get_documents_info_from_dataset_id(dataset_id=dataset_id)
    datasets = []
    for document in documents:
        datasets.append(
            DocumentInformation(
                id=str(document[0]),
                file_name=document[1],
                size=document[2],
                status=document[3],
                annotator=document[4],
                reviewer=document[5],
            )
        )
    return datasets


# TODO: Improve logic (currently its naive logic)
@protected_router.post(
    "/datasets/{dataset_id}/random-annotator-assignment",
    summary="Get a dataset with dataset-id",
    tags=["Datasets"],
)
async def assign_random_annotators_to_documents(dataset_id: str):
    documents = await get_unassigned_annotators_documents(dataset_id=dataset_id)
    annotators = await get_annotators()
    assignments = []
    for i, document_id in enumerate(documents):
        annotator_index = i % len(annotators)
        assignments.append(
            {"id": document_id[0], "annotator": annotators[annotator_index][0]}
        )
    await update_annotator_document_assignment(assignments)
    return JSONResponse(
        content={
            "detail": f"Random annotator assignment to documents in dataset with ID {dataset_id} is successful"
        },
    )


@protected_router.post(
    "/datasets/{dataset_id}/document-assignment",
    summary="Get a dataset with dataset-id",
    tags=["Datasets"],
)
async def assign_annotators_and_reviewers_to_documents(
    dataset_id: str, document_assignment_list: List[DocumentAssignment]
):
    doc_map = {}
    for document_assignment in document_assignment_list:
        doc_id = document_assignment.document_id
        if doc_id not in doc_map:
            doc_map[doc_id] = {"id": doc_id}
        doc_map[doc_id][document_assignment.type] = document_assignment.user_id

    assignments = list(doc_map.values())
    await update_annotator_document_assignment(assignments)
    return JSONResponse(
        content={
            "detail": f"Annotator/Reviewer assignment to documents in dataset with ID {dataset_id} is successful"
        },
    )


@protected_router.post("/indexing", summary="Index a dataset", tags=["Datasets"])
async def indexing(
    request: Request,
    index_request: IndexRequest,
    langchain_indexer: Annotated[LangchainIndexer, Depends(LangchainIndexer)],
    mailer: Annotated[Mailer, Depends(Mailer)],
):
    os.environ["OPENAI_API_TYPE"] = "openai"
    os.environ["OPENAI_API_KEY"] = index_request.openai_api_key
    documents, dataset_name = await get_documents_from_dataset_id(
        dataset_id=index_request.dataset_id
    )
    await langchain_indexer.index(
        collection_name=dataset_name,
        chunk_size=index_request.chunk_size,
        chunk_overlap_size=index_request.chunk_overlap_size,
        files_list=documents,
    )
    _, token = request.headers.get("authorization").split()
    user_name, _ = decode_token(token=token)
    user = await get_user_from_username(username=user_name)
    await mailer.send_indexing_email(
        recepient_email=user.email,
        recepient_name=user.name,
        dataset_name=dataset_name,
        dataset_id=index_request.dataset_id,
    )
    await set_indexed_status_to_dataset(dataset_id=index_request.dataset_id)
    return JSONResponse(
        content={"detail": "Dataset indexing is successful"},
    )


@protected_router.get(
    "/qna/document/{document_id}",
    summary="Get question and answers for a document id",
    response_model=QuestionAnswerList,
    tags=["QnA"],
)
async def get_question_answers_for_document(document_id: str):
    return await get_question_answers(document_id)


admin_app.include_router(protected_router)
admin_app.include_router(unprotected_router)
