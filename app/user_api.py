import os
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer

from lib.crud import (
    get_all_documents_to_be_reviewed,
    get_annotated_texts_from_version_id,
    get_chunk_results_for_qna_id,
    get_document_from_id,
    get_document_id_from_qna_id,
    get_documents,
    get_documents_from_user_id,
    get_latest_version_from_qna_id,
    get_qna_from_document_id,
    get_qna_from_id,
    get_user_from_id,
    get_user_from_username,
    get_version,
    get_versions_for_qna_id,
    insert_annotated_text,
    insert_chunk_result,
    insert_new_version,
    insert_qna,
    set_flag_to_query,
    set_last_edited_by_to_document,
    set_last_updated_at_to_qna,
    set_number_queries_to_document,
)
from lib.helper import (
    AnnotatedText,
    BaseDocument,
    BaseDocumentsList,
    ChunkResult,
    Document,
    DocumentInfo,
    DocumentsList,
    FlagQueryRequest,
    PostQnARequest,
    QueryResponse,
    QuestionAnswer,
    QuestionAnswerList,
    QuestionCategory,
    QuestionType,
    SingleQuestionAnswer,
    SingleQuestionAnswerList,
    SubmitRequest,
    compare_chunks,
    decode_token,
)
from retriever.retriever import (
    querying_with_hyde_pg_vector,
    querying_with_openai_pg_vector,
    querying_with_r2r,
)

jwt_http_bearer = HTTPBearer()
COLLECTION_NAME = os.environ["PGVECTOR_COLLECTION_NAME"]


def enforce_user_role(jwt_token: Annotated[str, Depends(jwt_http_bearer)]):
    _, role = decode_token(jwt_token.credentials)
    if role is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Role not found in token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not any(allowed_role in role for allowed_role in ["Annotator", "Reviewer"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have the necessary permissions",
        )


protected_router = APIRouter(dependencies=[Depends(enforce_user_role)])
unprotected_router = APIRouter(tags=["Config"])
user_app = FastAPI()


@user_app.exception_handler(Exception)
async def custom_exception_handler(request, exception):
    if hasattr(exception, "status_code"):
        status_code = exception.status_code
    else:
        status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return JSONResponse(status_code=status_code, content={"message": str(exception)})


@protected_router.get(
    "/documents",
    summary="Get all documents",
    response_model=DocumentsList,
    tags=["Document"],
)
async def get_all_documents():
    documents_list = await get_documents()
    documents = []
    for document in documents_list:
        if document.last_edited_by:
            user = await get_user_from_id(document.last_edited_by)
            name = user.name
        else:
            name = None
        documents.append(
            Document(
                id=str(document.id),
                file_name=document.name,
                last_edited_by=name,
                number_of_questions=document.number_of_queries,
            )
        )
    return DocumentsList(documents=documents)


@protected_router.get(
    "/document-titles",
    summary="Get all documents' titles",
    response_model=BaseDocumentsList,
    tags=["Document"],
)
async def get_all_documents_titles():
    documents_list = await get_documents()
    documents = []
    for document in documents_list:
        documents.append(
            BaseDocument(
                id=str(document.id),
                file_name=document.name,
            )
        )
    return BaseDocumentsList(documents=documents)


@protected_router.get(
    "/review-documents",
    summary="Get all documents to be reviewed",
    response_model=DocumentsList,
    tags=["Document"],
)
async def get_review_documents():
    documents_list = await get_all_documents_to_be_reviewed()
    documents = []
    for document in documents_list:
        if document.last_edited_by:
            user = await get_user_from_id(document.last_edited_by)
            name = user.name
        else:
            name = None
        documents.append(
            Document(
                id=str(document.id),
                file_name=document.name,
                last_edited_by=name,
                number_of_questions=document.number_of_queries,
            )
        )
    return DocumentsList(documents=documents)


@protected_router.get(
    "/documents/{document_id}",
    summary="Get a document from id",
    response_model=DocumentInfo,
    tags=["Document"],
)
async def get_document_info(document_id: str):
    try:
        document = await get_document_from_id(document_id=document_id)
        return DocumentInfo(
            id=str(document.id),
            file_name=document.name,
            content=document.content,
        )
    except Exception:
        return JSONResponse(
            content={"message": "Document not found"},
            status_code=status.HTTP_400_BAD_REQUEST,
        )


@protected_router.get(
    "/users/documents",
    summary="Get documents for the current user",
    response_model=DocumentsList,
    tags=["Document"],
)
async def get_documents_for_given_user(request: Request):
    _, token = request.headers.get("authorization").split()
    user_name = decode_token(token=token)
    user = await get_user_from_username(username=user_name)
    documents_list = await get_documents_from_user_id(user_id=user.id)
    documents = [
        Document(
            id=str(document.id),
            file_name=document.name,
            last_edited_by=user_name,
            number_of_questions=document.number_of_queries,
        )
        for document in documents_list
    ]
    return DocumentsList(documents=documents)


@protected_router.get(
    "/qna/document/{document_id}",
    summary="Get question and answers for a document id",
    response_model=QuestionAnswerList,
    tags=["Query"],
)
async def get_question_answers(document_id: str):
    try:
        qna_list = []
        qna = await get_qna_from_document_id(document_id=document_id)
        document = await get_document_from_id(document_id=document_id)
        for question in qna:
            qna_id = str(question.id)
            version = await get_latest_version_from_qna_id(qna_id=qna_id)
            chunk_results = await get_chunk_results_for_qna_id(qna_id=qna_id)
            raw_annotated_texts = await get_annotated_texts_from_version_id(
                version_id=version.id
            )
            answers = [
                AnnotatedText(
                    file_name=annotated_text.file_name,
                    text=annotated_text.text,
                    start_index=annotated_text.start_index,
                    end_index=annotated_text.end_index,
                    source_text=annotated_text.source_text,
                )
                for annotated_text in raw_annotated_texts
            ]
            chunk_results = [
                ChunkResult(
                    chunk=chunk_result.chunk_content,
                    metadata=chunk_result.chunk_metadata,
                    retriever_name=chunk_result.retriever_name,
                )
                for chunk_result in chunk_results
            ]
            qna_list.append(
                QuestionAnswer(
                    id=qna_id,
                    version_number=version.version_number,
                    file_name=document.name,
                    query=question.query,
                    query_type=question.query_type,
                    query_category=question.query_category,
                    flag=question.is_flagged,
                    answers=answers,
                    chunk_results=chunk_results,
                    additional_text=version.additional_info,
                    generation_response=version.generation_response,
                )
            )
        return QuestionAnswerList(qna=qna_list)
    except Exception:
        return JSONResponse(
            content={"message": "Incorrect Document ID"},
            status_code=status.HTTP_400_BAD_REQUEST,
        )


@protected_router.get(
    "/qna/{qna_id}",
    summary="Get question and answers for a qna id",
    response_model=SingleQuestionAnswerList,
    tags=["Query"],
)
async def get_all_question_answers(qna_id: str):
    try:
        qna = await get_qna_from_id(qna_id=qna_id)
        document = await get_document_from_id(document_id=qna.document_id)
        version_list = await get_versions_for_qna_id(qna_id=qna_id)
        chunk_results = await get_chunk_results_for_qna_id(qna_id=qna_id)
        chunk_results = [
            ChunkResult(
                chunk=chunk_result.chunk_content,
                metadata=chunk_result.chunk_metadata,
                retriever_name=chunk_result.retriever_name,
            )
            for chunk_result in chunk_results
        ]
        qna_list = []
        for version in version_list:
            version_id = str(version.id)
            raw_annotated_texts = await get_annotated_texts_from_version_id(
                version_id=version_id
            )
            answers = [
                AnnotatedText(
                    file_name=annotated_text.file_name,
                    text=annotated_text.text,
                    start_index=annotated_text.start_index,
                    end_index=annotated_text.end_index,
                    source_text=annotated_text.source_text,
                )
                for annotated_text in raw_annotated_texts
            ]
            qna_list.append(
                SingleQuestionAnswer(
                    version_number=version.version_number,
                    file_name=document.name,
                    query=qna.query,
                    query_type=qna.query_type,
                    query_category=qna.query_category,
                    answers=answers,
                    additional_text=version.additional_info,
                    generation_response=version.generation_response,
                )
            )
        return SingleQuestionAnswerList(
            qna=qna_list,
            id=qna_id,
            flag=qna.is_flagged,
            chunk_results=chunk_results,
        )
    except Exception:
        return JSONResponse(
            content={"message": "Incorrect QnA ID"},
            status_code=status.HTTP_400_BAD_REQUEST,
        )


@protected_router.post(
    "/qna/{qna_id}",
    summary="Create a new version of question and answers for a qna id",
    tags=["Query"],
)
async def post_qna_for_qna_id(
    qna_id: str, post_qna_request: PostQnARequest, request: Request
):
    _, token = request.headers.get("authorization").split()
    user_name = decode_token(token=token)
    user = await get_user_from_username(username=user_name)
    # TODO: Fix status here
    version = await insert_new_version(
        qna_id=qna_id,
        user_id=user.id,
        additional_text=post_qna_request.additional_answer,
        generation_response=post_qna_request.generation_response,
        status="",
    )
    document_id = await get_document_id_from_qna_id(qna_id=qna_id)
    current_date_time = datetime.now()
    await set_last_edited_by_to_document(
        document_id=document_id, user_id=user.id, current_date_time=current_date_time
    )
    await set_last_updated_at_to_qna(qna_id=qna_id, current_date_time=current_date_time)
    for annotated_text in post_qna_request.annotated_text:
        await insert_annotated_text(
            version_id=version.id,
            file_name=annotated_text.file_name,
            text=annotated_text.text,
            start_index=annotated_text.start_index,
            end_index=annotated_text.end_index,
            source_text=annotated_text.source_text,
        )
    return JSONResponse(content="Posted details successfully")


@protected_router.post(
    "/flag-query",
    summary="Flag the given query",
    tags=["Query"],
)
async def flag_query(flag_query_request: FlagQueryRequest):
    await set_flag_to_query(
        qna_id=flag_query_request.qna_id, is_flagged=flag_query_request.is_flagged
    )
    return JSONResponse(content="Question has been flagged successfully")


@protected_router.get(
    "/query",
    summary="Get retrieved chunks for a given query",
    response_model=QueryResponse,
    tags=["Query"],
)
async def query(
    query: str,
):
    try:
        openai_pg_vector_chunks = await querying_with_openai_pg_vector(
            collection_name=COLLECTION_NAME, query=query
        )
        r2r_chunks = await querying_with_r2r(query=query)
        hyde_pg_vector_chunks = await querying_with_hyde_pg_vector(
            collection_name=COLLECTION_NAME, query=query
        )
        final_chunks = await compare_chunks(
            openai_pg_vector_chunks, r2r_chunks, hyde_pg_vector_chunks
        )
        return QueryResponse(query=query, chunks=final_chunks)
    except Exception as e:
        return JSONResponse(
            content={"message": e.__str__()},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@protected_router.post(
    "/submit",
    summary="Submit the annotated texts along with the query",
    tags=["Query"],
)
async def submit(submit_request: SubmitRequest, request: Request):
    document_id = submit_request.document_id
    _, token = request.headers.get("authorization").split()
    user_name, _ = decode_token(token=token)
    user = await get_user_from_username(username=user_name)
    await set_number_queries_to_document(document_id=document_id, user_id=user.id)
    qna = await insert_qna(
        document_id=document_id,
        query=submit_request.query,
        query_type=submit_request.query_type,
        query_category=submit_request.query_category,
    )
    qna_id = qna.id
    for chunk_result in submit_request.chunk_result:
        await insert_chunk_result(
            qna_id=qna_id,
            chunk=chunk_result.chunk,
            metadata=chunk_result.metadata,
            retriever_name=chunk_result.retriever_name,
        )
    version = await get_version(
        qna_id=qna_id,
        user_id=user.id,
        additional_text=submit_request.additional_answer,
        generation_response=submit_request.generation_response,
    )
    for annotated_text in submit_request.annotated_text:
        await insert_annotated_text(
            version_id=version.id,
            file_name=annotated_text.file_name,
            text=annotated_text.text,
            start_index=annotated_text.start_index,
            end_index=annotated_text.end_index,
            source_text=annotated_text.source_text,
        )
    return JSONResponse(content="Submitted details successfully")


@unprotected_router.get(
    "/question-config",
    summary="Get question config for the current environment",
)
async def question_config():
    return JSONResponse(
        content={
            "question_type": [
                {"label": question_type.value, "value": question_type.name}
                for question_type in QuestionType
            ],
            "question_category": [
                {"label": question_category.value, "value": question_category.name}
                for question_category in QuestionCategory
            ],
        }
    )


user_app.include_router(protected_router)
user_app.include_router(unprotected_router)
