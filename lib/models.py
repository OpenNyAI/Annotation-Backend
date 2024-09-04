import uuid

from sqlalchemy import (
    ARRAY,
    JSON,
    TIMESTAMP,
    UUID,
    Boolean,
    Column,
    ForeignKey,
    Integer,
    String,
)
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.sql import func

Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    created_at = Column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )
    last_logged_in = Column(TIMESTAMP(timezone=True))

    user_role = relationship("UserRole", back_populates="user")
    datasets = relationship(
        "Dataset", back_populates="user", cascade="all, delete-orphan"
    )
    documents = relationship(
        "Document", back_populates="user", cascade="all, delete-orphan"
    )
    reset_passwords = relationship(
        "ResetPassword", back_populates="user", cascade="all, delete-orphan"
    )
    versions = relationship(
        "Version", back_populates="user", cascade="all, delete-orphan"
    )


class Role(Base):
    __tablename__ = "roles"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False)
    user_role = relationship("UserRole", back_populates="roles")


class UserRole(Base):
    __tablename__ = "user_roles"
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), primary_key=True)
    role_id = Column(UUID(as_uuid=True), ForeignKey("roles.id"), primary_key=True)
    user = relationship("User", back_populates="user_role")
    roles = relationship("Role", back_populates="user_role")


class Dataset(Base):
    __tablename__ = "datasets"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False)
    description = Column(String, nullable=False)
    status = Column(
        String, nullable=False, default="Not Indexed"
    )  # Indexed | Not Indexed
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    created_at = Column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )
    documents = relationship(
        "Document", back_populates="dataset", cascade="all, delete-orphan"
    )
    user = relationship("User", back_populates="datasets")


class Document(Base):
    __tablename__ = "documents"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    dataset_id = Column(UUID(as_uuid=True), ForeignKey("datasets.id"))
    name = Column(String, nullable=False)
    content = Column(String, nullable=False)
    number_of_queries = Column(Integer, default=0)
    status = Column(
        String, nullable=False, default="Annotation"
    )  # Annotation | Review
    created_at = Column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )
    last_edited_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    last_edited_at = Column(TIMESTAMP(timezone=True))
    user = relationship("User", back_populates="documents")
    dataset = relationship("Dataset", back_populates="documents")


class QnA(Base):
    __tablename__ = "qna"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    document_id = Column(UUID(as_uuid=True), ForeignKey("documents.id"))
    query = Column(String, nullable=False)
    query_type = Column(String, nullable=False)  # Simple | Medium | Complex
    query_category = Column(String, nullable=False)  # Any Category
    is_flagged = Column(Boolean, default=False)
    created_at = Column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )
    last_updated_at = Column(TIMESTAMP(timezone=True))
    versions = relationship(
        "Version", back_populates="qna", cascade="all, delete-orphan"
    )
    chunk_results = relationship(
        "ChunkResult", back_populates="qna", cascade="all, delete-orphan"
    )


class ChunkResult(Base):
    __tablename__ = "chunk_result"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    qna_id = Column(UUID(as_uuid=True), ForeignKey("qna.id"))
    chunk_content = Column(String, nullable=False)
    chunk_metadata = Column(JSON, nullable=False)
    retriever_name = Column(String, nullable=False)
    qna = relationship("QnA", back_populates="chunk_results")


class Version(Base):
    __tablename__ = "version"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    qna_id = Column(UUID(as_uuid=True), ForeignKey("qna.id"))
    version_number = Column(Integer, nullable=False)
    additional_info = Column(ARRAY(JSON))
    generation_response = Column(String)
    status = Column(String, nullable=False)  # Annotation | Review
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    created_at = Column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )
    qna = relationship("QnA", back_populates="versions")
    user = relationship("User", back_populates="versions")
    annotated_texts = relationship(
        "AnnotatedText", back_populates="version", cascade="all, delete-orphan"
    )


class AnnotatedText(Base):
    __tablename__ = "annotated_text"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    version_id = Column(UUID(as_uuid=True), ForeignKey("version.id"))
    file_name = Column(String, nullable=False)
    text = Column(String, nullable=False)
    start_index = Column(Integer, nullable=False)
    end_index = Column(Integer, nullable=False)
    source_text = Column(String, default=None)
    created_at = Column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )
    version = relationship("Version", back_populates="annotated_texts")


class ResetPassword(Base):
    __tablename__ = "reset_password"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    verification_code = Column(String, nullable=False)
    expiry_time = Column(TIMESTAMP(timezone=True), nullable=False)
    user = relationship("User", back_populates="reset_passwords")
