import json
import os
import tempfile
from datetime import datetime, timedelta
from email.message import EmailMessage
from enum import Enum
from smtplib import SMTP
from typing import List, Optional

import docx2txt
import fitz
from fastapi import HTTPException, status
from fastapi.datastructures import UploadFile
from jinja2 import Template
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, ValidationError

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
jwt_secret_key = os.environ["JWT_TOKEN_SECRET_KEY"]
jwt_algorithm = os.environ["JWT_TOKEN_ALGORITHM"]
app_base_url = os.environ["FRONTEND_APP_BASE_URL"]
app_sub_url = os.environ["FRONTEND_APP_SUB_URL"]
base_email = os.environ["BASE_EMAIL"]
base_email_app_password = os.environ["BASE_EMAIL_APP_PASSWORD"]
smtp_host = os.environ["SMTP_HOST"]
smtp_port = os.environ["SMTP_PORT"]


class SignupRequest(BaseModel):
    name: str
    username: str
    email: str
    password: str


class ResetPasswordRequest(BaseModel):
    email: str


class UpdatePasswordRequest(BaseModel):
    reset_id: str
    verification_code: str
    new_password: str


class AnnotatedText(BaseModel):
    file_name: str
    text: str
    start_index: int
    end_index: int
    source_text: Optional[str]


class ChunkResult(BaseModel):
    chunk: str
    metadata: Optional[dict]
    retriever_name: str


class SubmitRequest(BaseModel):
    query: str
    query_type: str
    query_category: str
    document_id: str
    annotated_text: List[AnnotatedText]
    chunk_result: List[ChunkResult]
    additional_answer: List[dict]
    generation_response: str


class PostQnARequest(BaseModel):
    annotated_text: List[AnnotatedText]
    additional_answer: List[dict]
    generation_response: str


class FlagQueryRequest(BaseModel):
    qna_id: str
    is_flagged: bool


class IndexRequest(BaseModel):
    dataset_id: str
    openai_api_key: str
    chunk_size: int
    chunk_overlap_size: int


class BaseDocument(BaseModel):
    id: str
    file_name: str


class DocumentInformation(BaseDocument):
    size: int
    status: str
    annotator: Optional[str]
    reviewer: Optional[str]


class Document(BaseDocument):
    last_edited_by: str | None
    number_of_questions: int


class BaseDocumentsList(BaseModel):
    documents: List[BaseDocument]


class DocumentsList(BaseModel):
    documents: List[Document]


class SingleQuestionAnswer(BaseModel):
    version_number: int
    file_name: str
    query: str
    query_type: str
    query_category: str
    answers: List[AnnotatedText]
    additional_text: List[dict]
    generation_response: str


class QuestionAnswer(SingleQuestionAnswer):
    id: str
    flag: bool
    chunk_results: List[ChunkResult]


class QueryResponse(BaseModel):
    query: str
    chunks: List[dict]


class QuestionAnswerList(BaseModel):
    qna: List[QuestionAnswer]


class SingleQuestionAnswerList(BaseModel):
    id: str
    flag: bool
    chunk_results: List[ChunkResult]
    qna: List[SingleQuestionAnswer]


class DocumentInfo(BaseModel):
    id: str
    file_name: str
    content: str


class QuestionType(Enum):
    Simple = "Simple"
    Medium = "Medium"
    Complex = "Complex"


class QuestionCategory(Enum):
    LawLanguageQuestion = "Law Language Question"
    NaturalLanguageQuestion = "Natural Language Question"


class User(BaseModel):
    id: str
    name: str
    username: str
    email: str
    roles: List[str]


class UserRoleUpdate(BaseModel):
    user_id: str
    role_id: str


class Dataset(BaseModel):
    id: str
    name: str
    description: str
    status: str
    created_by: str


class RoleCache:
    _instance = None
    roles = []

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(RoleCache, cls).__new__(cls)
        return cls._instance

    @classmethod
    def update_roles(cls, new_roles: list):
        cls.roles = new_roles

    @classmethod
    def get_role_id(cls, role_name: str) -> str:
        for role in cls.roles:
            if role["role_name"] == role_name:
                return role["role_id"]


class DocumentParser:
    _instance = None
    parsers = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DocumentParser, cls).__new__(cls)
        cls.parsers = {
            ".pdf": cls.pdf_parser,
            ".docx": cls.docx_parser,
            ".json": cls.json_parser,
        }
        return cls._instance

    @classmethod
    def parse_file(cls, file: UploadFile) -> str:
        file_extension = os.path.splitext(file.filename)[1]
        with tempfile.NamedTemporaryFile(
            suffix=file_extension,
        ) as temp_file:
            content = file.file.read()
            temp_file.write(content)
            file_path = temp_file.name
            parser = cls.parsers.get(file_extension, cls.default_parser)
            return parser(file_path)

    @classmethod
    def docx_parser(cls, docx_file_path: str):
        return docx2txt.process(docx_file_path)

    @classmethod
    def pdf_parser(cls, pdf_file_path: str):
        doc = fitz.open(pdf_file_path)
        return "\n".join(page.get_text("text") for page in doc)

    @classmethod
    def json_parser(cls, json_file_path: str):
        with open(json_file_path, "r") as file:
            data = json.load(file)
        return json.dumps(data, indent=4)

    @classmethod
    def default_parser(cls, file_path: str):
        with open(file_path, "r") as file:
            return file.read()


def get_hashed_password(password: str) -> str:
    return password_context.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return password_context.verify(password, hashed_password)


def create_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire_time = datetime.utcnow() + expires_delta
    else:
        expire_time = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire_time})
    encoded_jwt_token = jwt.encode(
        claims=to_encode, key=jwt_secret_key, algorithm=jwt_algorithm
    )
    return encoded_jwt_token


def decode_token(token: str) -> str:
    try:
        payload = jwt.decode(
            token=token,
            key=jwt_secret_key,
            algorithms=[jwt_algorithm],
        )
        if datetime.fromtimestamp(payload["exp"]) < datetime.now():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return payload["username"], payload["role"]
    except (JWTError, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


def check_token_validity(token: str) -> bool:
    payload = jwt.decode(
        token=token,
        key=jwt_secret_key,
        algorithms=[jwt_algorithm],
    )
    if datetime.fromtimestamp(payload["exp"]) < datetime.now():
        return False
    else:
        return True


async def compare_chunks(chunk_one, chunk_two, chunk_three):
    combined_chunk_list = (
        [(chunk, "Retriever-1") for chunk in chunk_one]
        + [(chunk, "Retriever-2") for chunk in chunk_two]
        + [(chunk, "Retriever-3") for chunk in chunk_three]
    )

    ans_list = []
    unique_chunk_list = []
    for chunk, retriever_name in combined_chunk_list:
        if chunk not in unique_chunk_list:
            unique_chunk_list.append(chunk)
            new_chunk_with_name = chunk.copy()
            new_chunk_with_name["retriever_name"] = retriever_name
            ans_list.append(new_chunk_with_name)

    return ans_list


class Mailer:
    _instance = None
    server = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Mailer, cls).__new__(cls)
            cls._init_server()
        return cls._instance

    @classmethod
    def _init_server(cls):
        cls.server = SMTP(smtp_host, smtp_port)
        cls.server.starttls()
        cls.server.login(base_email, base_email_app_password)

    @classmethod
    def _send_email(cls, recepient_email: str, subject: str, html_content: str):
        message = EmailMessage()
        message.add_alternative(html_content, subtype="html")
        message["Subject"] = subject
        message["From"] = base_email
        message["To"] = recepient_email
        cls.server.send_message(message)

    @classmethod
    def _render_template(cls, template_str: str, **kwargs) -> str:
        template = Template(template_str)
        return template.render(**kwargs)

    @classmethod
    async def send_email(
        cls, recepient_email: str, subject: str, template: str, **kwargs
    ):
        html_content = cls._render_template(template, **kwargs)
        cls._send_email(recepient_email, subject, html_content)

    @classmethod
    async def send_reset_password_email(
        cls,
        recepient_email: str,
        recepient_name: str,
        reset_id: str,
        verification_code: str,
    ):
        verification_link = (
            f"{app_base_url}/{app_sub_url}?reset_id={reset_id}"
            f"&verification_code={verification_code}"
        )
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <style>
            body {
                font-family: Arial, sans-serif;
                background-color: #f2f2f2;
            }
            .container {
                padding: 20px;
                background-color: white;
                border-radius: 10px;
                box-shadow: 0px 0px 5px 2px gray;
            }
            .header {
                color: #333;
                font-size: 24px;
                text-align: center;
            }
            .content {
                color: #1c1c1c;
                font-size: 18px;
                margin-top: 20px;
                text-align: center;
            }
            .verification-link {
                color: black;
                font-family: Roboto-Regular, Helvetica, Arial, sans-serif;
                font-size: 24px;
                text-align: center;
            }
            .signature {
                font-size: 17px;
                margin-top: 40px;
                text-align: center;
            }
            .do-not-reply {
                color: red;
                font-style: italic;
                font-size: 12px;
                margin-top: 30px;
                text-align: center;
            }
            a:link {
                color: blue;
            }
            a:visited {
                color: purple;
            }
            </style>
        </head>
        <body>
            <div class="container">
            <div class="header">Hi {{recepient_name}}!</div>
            <div class="content">
                <p>
                Forgot your password?<br />We received a request to reset the password
                for your account.<br /><br />To reset your password, please click on
                the link given below:
                </p>
            </div>
            <div class="verification-link">
                <a href={{verification_link}}>Password Reset</a>
            </div>
            <div class="content">
                <p>This password reset link is only valid for the next 15 minutes.</p>
                <p>If you didn't make this request, please ignore this email.</p>
            </div>
            <div class="signature">Thanks,<br />OpenNyAI team.</div>
            <div class="do-not-reply">Note: Please do not reply to this mail.</div>
            </div>
        </body>
        </html>
        """
        await cls.send_email(
            recepient_email,
            "Password Reset Code",
            html_template,
            recepient_name=recepient_name,
            verification_link=verification_link,
        )

    @classmethod
    async def send_indexing_email(
        cls,
        recepient_email: str,
        recepient_name: str,
        dataset_name: str,
        dataset_id: str,
    ):
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <style>
            body {
                font-family: Arial, sans-serif;
                background-color: #f2f2f2;
            }
            .container {
                padding: 20px;
                background-color: white;
                border-radius: 10px;
                box-shadow: 0px 0px 5px 2px gray;
            }
            .header {
                color: #333;
                font-size: 24px;
                text-align: center;
            }
            .content {
                color: #1c1c1c;
                font-size: 20px;
                margin-top: 20px;
                text-align: center;
            }
            .signature {
                font-size: 17px;
                margin-top: 40px;
                text-align: center;
            }
            .do-not-reply {
                color: red;
                font-style: italic;
                font-size: 12px;
                margin-top: 30px;
                text-align: center;
            }
            a:link {
                color: blue;
            }
            a:visited {
                color: purple;
            }
            </style>
        </head>
        <body>
            <div class="container">
            <div class="header">Hi {{recepient_name}}!</div>
            <div class="content">
                The indexing for your dataset <b>{{dataset_name}}</b> with ID <b>{{dataset_id}}</b> is done!
            </div>
            <div class="signature">Thanks,<br />OpenNyAI team.</div>
            <div class="do-not-reply">Note: Please do not reply to this mail.</div>
            </div>
        </body>
        </html>
        """
        await cls.send_email(
            recepient_email,
            "Indexing is done!",
            html_template,
            recepient_name=recepient_name,
            dataset_name=dataset_name,
            dataset_id=dataset_id,
        )

    @classmethod
    async def send_document_assignment_email(
        cls,
        recepient_email: str,
        recepient_name: str,
        document_name: str,
        role: str,
    ):
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <style>
            body {
                font-family: Arial, sans-serif;
                background-color: #f2f2f2;
            }
            .container {
                padding: 20px;
                background-color: white;
                border-radius: 10px;
                box-shadow: 0px 0px 5px 2px gray;
            }
            .header {
                color: #333;
                font-size: 24px;
                text-align: center;
            }
            .content {
                color: #1c1c1c;
                font-size: 20px;
                margin-top: 20px;
                text-align: center;
            }
            .signature {
                font-size: 17px;
                margin-top: 40px;
                text-align: center;
            }
            .do-not-reply {
                color: red;
                font-style: italic;
                font-size: 12px;
                margin-top: 30px;
                text-align: center;
            }
            a:link {
                color: blue;
            }
            a:visited {
                color: purple;
            }
            </style>
        </head>
        <body>
            <div class="container">
            <div class="header">Hi {{recepient_name}}!</div>
            <div class="content">
                You have been assigned the document <b>{{document_name}}</b> at the <b>{{role}}</b> role by your admin!
            </div>
            <div class="signature">Thanks,<br />OpenNyAI team.</div>
            <div class="do-not-reply">Note: Please do not reply to this mail.</div>
            </div>
        </body>
        </html>
        """
        await cls.send_email(
            recepient_email,
            "You have been assigned a document!",
            html_template,
            recepient_name=recepient_name,
            document_name=document_name,
            role=role,
        )

    @classmethod
    def quit(cls):
        if cls.server:
            cls.server.quit()
