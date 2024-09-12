import os

import asyncpg
from dotenv import load_dotenv
from langchain.docstore.document import Document
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_openai import AzureOpenAIEmbeddings, OpenAIEmbeddings
from langchain_postgres.vectorstores import PGVector

load_dotenv()


class LangchainIndexer:
    def __init__(self):
        self.db_name = os.getenv("POSTGRES_DATABASE_NAME")
        self.db_user = os.getenv("POSTGRES_DATABASE_USERNAME")
        self.db_password = os.getenv("POSTGRES_DATABASE_PASSWORD")
        self.db_host = os.getenv("POSTGRES_DATABASE_HOST")
        self.db_port = os.getenv("POSTGRES_DATABASE_PORT")
        self.db_url = f"postgresql+psycopg2://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"

    async def create_pg_vector_index_if_not_exists(self):
        print("Inside create_pg_vector_index_if_not_exists")
        connection = await asyncpg.connect(
            host=self.db_host,
            user=self.db_user,
            password=self.db_password,
            database=self.db_name,
            port=self.db_port,
        )
        try:
            async with connection.transaction():
                await connection.execute(
                    "ALTER TABLE langchain_pg_embedding ALTER COLUMN embedding TYPE vector(1536)"
                )
                await connection.execute(
                    "CREATE INDEX IF NOT EXISTS langchain_embeddings_hnsw ON langchain_pg_embedding USING hnsw (embedding vector_cosine_ops)"
                )
        finally:
            await connection.close()

    async def index(
        self,
        collection_name: str,
        chunk_size: int,
        chunk_overlap_size: int,
        files_list: list,
    ):
        splitter = RecursiveCharacterTextSplitter(
            chunk_size=chunk_size,
            chunk_overlap=chunk_overlap_size,
            separators=["\n\n", "\n", ".", " ", ""],
        )
        source_chunks = []
        counter = 1
        for file in files_list:
            file_name = file[0]
            content = file[1]
            for chunk in splitter.split_text(content):
                new_metadata = {
                    "chunk_id": str(counter),
                    "file_name": file_name,
                }
                source_chunks.append(Document(page_content=chunk, metadata=new_metadata))
                counter += 1
        try:
            if os.environ["OPENAI_API_TYPE"] == "azure":
                embeddings = AzureOpenAIEmbeddings(
                    model="text-embedding-ada-002",
                    azure_deployment=os.environ["AZURE_OPENAI_EMBEDDINGS_DEPLOYMENT"],
                    azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
                    openai_api_type=os.environ["OPENAI_API_TYPE"],
                    openai_api_key=os.environ["OPENAI_API_KEY"],
                )
            else:
                embeddings = OpenAIEmbeddings(client="")
            db = PGVector.from_documents(
                embedding=embeddings,
                documents=source_chunks,
                collection_name=collection_name,
                connection=self.db_url,
                pre_delete_collection=True,
            )
            print(
                f"Embeddings have been created for the collection: {db.collection_name}"
            )
            await self.create_pg_vector_index_if_not_exists()
            print("Indexing done!")
        except Exception as e:
            raise Exception(e.__str__())
