from datetime import datetime
from typing import List

from sqlalchemy import asc, delete, desc, func, insert, select, update
from sqlalchemy.orm import aliased

from .db_connection import async_session
from .models import (
    AnnotatedText,
    ChunkResult,
    Dataset,
    Document,
    QnA,
    ResetPassword,
    Role,
    User,
    UserRole,
    Version,
)


async def get_user_from_username(username: str) -> User:
    query = select(User).where(User.username == username)
    async with async_session() as session:
        async with session.begin():
            result = await session.execute(query)
            user = result.scalars().first()
            return user
    return None


async def get_roles_from_user_id(user_id: str) -> List[Role]:
    query = (
        select(Role)
        .join(UserRole, UserRole.role_id == Role.id)
        .where(UserRole.user_id == user_id)
    )
    async with async_session() as session:
        async with session.begin():
            result = await session.execute(query)
            roles = result.scalars().all()
            return roles
    return None


async def get_all_roles() -> List[Role]:
    query = select(Role)
    async with async_session() as session:
        async with session.begin():
            result = await session.execute(query)
            roles = result.scalars().all()
            return roles
    return None


async def get_user_roles():
    query = (
        select(User, UserRole.role_id.label("role_id"))
        .join(UserRole, User.id == UserRole.user_id)
        .join(Role, Role.id == UserRole.role_id)
        .where(Role.name != "Admin")
    )
    async with async_session() as session:
        async with session.begin():
            result = await session.execute(query)
            user_role_mapping = result.fetchall()
            return user_role_mapping
    return None


async def insert_user_role(user_id: str, role_id: str):
    user_role = UserRole(user_id=user_id, role_id=role_id)
    async with async_session() as session:
        async with session.begin():
            session.add(user_role)
            await session.commit()


async def update_user_roles(user_roles: list):
    user_ids = {user_role["user_id"] for user_role in user_roles}

    async with async_session() as session:
        async with session.begin():
            delete_query = delete(UserRole).where(UserRole.user_id.in_(user_ids))
            await session.execute(delete_query)

            insert_query = insert(UserRole).values(user_roles)
            await session.execute(insert_query)
            await session.commit()


async def create_user(
    name: str, username: str, email: str, password: str, role_id: str
):
    async with async_session() as session:
        async with session.begin():
            user = User(name=name, username=username, email=email, password=password)
            session.add(user)
            await session.flush()  # Ensure user.id is available after flush

            user_role = UserRole(user_id=user.id, role_id=role_id)
            session.add(user_role)


async def create_dataset(
    name: str, description: str, created_by: str, documents_list: list
):
    documents = []
    dataset = Dataset(name=name, description=description, created_by=created_by)
    async with async_session() as session:
        async with session.begin():
            session.add(dataset)
            await session.flush()
            for document in documents_list:
                documents.append(
                    Document(
                        dataset_id=dataset.id,
                        name=document["file_name"],
                        size=document["size"],
                        content=document["content"],
                    )
                )
            session.add_all(documents)
            await session.commit()


async def set_last_logged_in(username: str, last_logged_in: str):
    async with async_session() as session:
        async with session.begin():
            query = (
                update(User)
                .where(User.username == username)
                .values(last_logged_in=last_logged_in)
            )
            await session.execute(query)
            await session.commit()


async def get_user_from_email(email: str) -> User:
    query = select(User).where(User.email == email)
    async with async_session() as session:
        async with session.begin():
            result = await session.execute(query)
            user = result.scalars().first()
            return user
    return None


async def insert_reset_password(
    user_id: str, verification_code: str, expiry_time: datetime
) -> ResetPassword:
    reset_password = ResetPassword(
        user_id=user_id, verification_code=verification_code, expiry_time=expiry_time
    )
    async with async_session() as session:
        async with session.begin():
            session.add(reset_password)
            await session.commit()
            return reset_password


async def get_reset_password(reset_id: str, verification_code: str) -> ResetPassword:
    query = (
        select(ResetPassword)
        .where(ResetPassword.id == reset_id)
        .where(ResetPassword.verification_code == verification_code)
    )
    async with async_session() as session:
        async with session.begin():
            result = await session.execute(query)
            reset_password = result.scalars().first()
            return reset_password
    return None


async def update_user_password(user_id: str, new_password: str):
    async with async_session() as session:
        async with session.begin():
            stmt = update(User).where(User.id == user_id).values(password=new_password)
            await session.execute(stmt)
            await session.commit()


async def get_datasets():
    query = (
        select(Dataset, User.name)
        .join(User, User.id == Dataset.created_by)
        .order_by(asc(Dataset.name))
    )
    async with async_session() as session:
        async with session.begin():
            result = await session.execute(query)
            datasets_with_username = result.fetchall()
            return datasets_with_username


async def get_documents_from_dataset_id(dataset_id: str):
    annotator = aliased(User)
    reviewer = aliased(User)
    query = (
        select(
            Document.id,
            Document.name,
            Document.size,
            Document.status,
            annotator.username.label("annotator_username"),
            reviewer.username.label("reviewer_username"),
        )
        .outerjoin(annotator, Document.annotator == annotator.id)
        .outerjoin(reviewer, Document.reviewer == reviewer.id)
        .where(Document.dataset_id == dataset_id)
        .order_by(asc(Document.name))
    )
    async with async_session() as session:
        async with session.begin():
            result = await session.execute(query)
            documents_with_usernames = result.fetchall()
            return documents_with_usernames
    return None


async def get_documents() -> List[Document]:
    query = select(Document).order_by(asc(Document.name))
    async with async_session() as session:
        async with session.begin():
            result = await session.execute(query)
            documents = result.scalars().all()
            return documents
    return None


async def get_all_documents_to_be_reviewed() -> List[Document]:
    query = (
        select(Document)
        .where(Document.number_of_queries > 0)
        .order_by(asc(Document.name))
    )
    async with async_session() as session:
        async with session.begin():
            result = await session.execute(query)
            documents = result.scalars().all()
            return documents
    return None


async def get_document_from_id(document_id: str) -> Document:
    query = select(Document).where(Document.id == document_id)
    async with async_session() as session:
        async with session.begin():
            result = await session.execute(query)
            document = result.scalars().first()
            return document
    return None


async def set_last_edited_by_to_document(
    document_id: str, user_id: str, current_date_time: datetime
):
    async with async_session() as session:
        async with session.begin():
            query = (
                update(Document)
                .where(Document.id == document_id)
                .values(
                    last_edited_by=user_id,
                    last_edited_at=current_date_time,
                )
            )
            await session.execute(query)
            await session.commit()


async def set_last_updated_at_to_qna(qna_id: str, current_date_time: datetime):
    async with async_session() as session:
        async with session.begin():
            query = (
                update(QnA)
                .where(QnA.id == qna_id)
                .values(
                    last_updated_at=current_date_time,
                )
            )
            await session.execute(query)
            await session.commit()


async def set_number_queries_to_document(document_id: str, user_id: str):
    async with async_session() as session:
        async with session.begin():
            query = (
                update(Document)
                .where(Document.id == document_id)
                .values(
                    last_edited_by=user_id,
                    number_of_queries=Document.number_of_queries + 1,
                    last_edited_at=datetime.now(),
                )
            )
            await session.execute(query)
            await session.commit()


async def set_flag_to_query(qna_id: str, is_flagged: bool):
    async with async_session() as session:
        async with session.begin():
            query = update(QnA).where(QnA.id == qna_id).values(is_flagged=is_flagged)
            await session.execute(query)
            await session.commit()


async def get_documents_from_user_id(user_id: str) -> List[Document]:
    query = (
        select(Document)
        .distinct(Document.id)
        .join(Version, Version.created_by == user_id)
        .join(QnA, QnA.id == Version.qna_id)
        .where(Document.id == QnA.document_id)
    )
    async with async_session() as session:
        async with session.begin():
            result = await session.execute(query)
            documents = result.scalars().all()
            return documents
    return None


async def get_qna_from_document_id(document_id: str) -> List[QnA]:
    query = select(QnA).where(QnA.document_id == document_id).order_by(desc(QnA.id))
    async with async_session() as session:
        async with session.begin():
            result = await session.execute(query)
            qna = result.scalars().all()
            return qna
    return None


async def get_qna_from_id(qna_id: str) -> QnA:
    query = select(QnA).where(QnA.id == qna_id)
    async with async_session() as session:
        async with session.begin():
            result = await session.execute(query)
            qna = result.scalars().first()
            return qna
    return None


async def get_latest_version_from_qna_id(qna_id: str) -> Version:
    query = (
        select(Version)
        .where(Version.qna_id == qna_id)
        .order_by(desc(Version.version_number), desc(Version.created_at))
        .limit(1)
    )
    async with async_session() as session:
        async with session.begin():
            result = await session.execute(query)
            version = result.scalars().first()
            return version
    return None


async def get_annotated_texts_from_version_id(version_id: str) -> List[AnnotatedText]:
    query = (
        select(AnnotatedText)
        .where(AnnotatedText.version_id == version_id)
        .order_by(asc(AnnotatedText.created_at))
    )
    async with async_session() as session:
        async with session.begin():
            result = await session.execute(query)
            annotated_texts = result.scalars().all()
            return annotated_texts
    return None


async def get_user_from_id(user_id: str) -> User:
    query = select(User).where(User.id == user_id)
    async with async_session() as session:
        async with session.begin():
            result = await session.execute(query)
            user = result.scalars().first()
            return user
    return None


async def insert_qna(
    document_id: str, query: str, query_type: str, query_category: str
) -> QnA:
    qna = QnA(
        document_id=document_id,
        query=query,
        query_type=query_type,
        query_category=query_category,
        last_updated_at=datetime.now(),
    )
    async with async_session() as session:
        async with session.begin():
            session.add(qna)
            await session.commit()
            return qna
    return None


async def insert_chunk_result(
    qna_id: str, chunk: str, metadata: dict, retriever_name: str
) -> ChunkResult:
    chunk_result = ChunkResult(
        qna_id=qna_id, chunk=chunk, metadata_=metadata, retriever_name=retriever_name
    )
    async with async_session() as session:
        async with session.begin():
            session.add(chunk_result)
            await session.commit()
            return chunk_result
    return None


async def get_version(
    qna_id: str, user_id: str, additional_text: list, generation_response: str
) -> Version:
    query = (
        select(Version)
        .where(Version.qna_id == qna_id)
        .where(Version.created_by == user_id)
        .order_by(desc(Version.created_at))
    )
    async with async_session() as session:
        async with session.begin():
            result = await session.execute(query)
            version = result.scalars().first()
            if version is None:
                version = Version(
                    qna_id=qna_id,
                    created_by=user_id,
                    version_number=1,
                    additional_info=additional_text,
                    generation_response=generation_response,
                )
                session.add(version)
                await session.commit()
            return version
    return None


async def get_versions_for_qna_id(qna_id: str) -> List[Version]:
    query = (
        select(Version)
        .where(Version.qna_id == qna_id)
        .order_by(desc(Version.version_number))
    )
    async with async_session() as session:
        async with session.begin():
            result = await session.execute(query)
            versions = result.scalars().all()
            return versions
    return None


async def get_document_id_from_qna_id(qna_id: str) -> str:
    query = select(QnA.document_id).where(QnA.id == qna_id)
    async with async_session() as session:
        async with session.begin():
            result = await session.execute(query)
            document_id = result.scalars().first()
            return document_id
    return None


async def get_chunk_results_for_qna_id(qna_id: str) -> List[ChunkResult]:
    query = select(ChunkResult).where(ChunkResult.qna_id == qna_id)
    async with async_session() as session:
        async with session.begin():
            result = await session.execute(query)
            chunk_results = result.scalars().all()
            return chunk_results
    return None


async def insert_annotated_text(
    version_id: str,
    file_name: str,
    text: str,
    start_index: int,
    end_index: int,
    source_text: str = None,
):
    annotated_text = AnnotatedText(
        file_name=file_name,
        text=text,
        start_index=start_index,
        end_index=end_index,
        source_text=source_text,
        version_id=version_id,
    )
    async with async_session() as session:
        async with session.begin():
            session.add(annotated_text)
            await session.commit()


async def insert_new_version(
    qna_id: str,
    user_id: str,
    additional_text: list,
    generation_response: str,
    status: str,
):
    async with async_session() as session:
        async with session.begin():
            result = await session.execute(
                select(func.max(Version.version_number)).where(Version.qna_id == qna_id)
            )
            max_version_number = result.scalar()
            version_number = max_version_number + 1
            version = Version(
                qna_id=qna_id,
                created_by=user_id,
                version_number=version_number,
                additional_info=additional_text,
                generation_response=generation_response,
                status=status,
            )
            session.add(version)
            await session.commit()
            return version
    return None
