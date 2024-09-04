import os

import requests
from dotenv import load_dotenv
from langchain.chains.hyde.base import HypotheticalDocumentEmbedder
from langchain_openai import AzureOpenAIEmbeddings, OpenAI, OpenAIEmbeddings
from langchain_postgres.vectorstores import PGVector

load_dotenv()


db_name = os.getenv("POSTGRES_DATABASE_NAME")
db_user = os.getenv("POSTGRES_DATABASE_USERNAME")
db_password = os.getenv("POSTGRES_DATABASE_PASSWORD")
db_host = os.getenv("POSTGRES_DATABASE_HOST")
db_port = os.getenv("POSTGRES_DATABASE_PORT")
r2r_search_api_url = os.getenv("R2R_SEARCH_API")
db_url = f"postgresql+psycopg2://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"

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


async def querying_with_openai_pg_vector(
    collection_name: str,
    query: str,
    top_chunk_k_value: int = 5,
    metadata: dict = None,
):
    search_index = PGVector(
        embeddings=embeddings,
        connection=db_url,
        collection_name=collection_name,
    )
    if metadata:
        documents = search_index.similarity_search(
            query=query, k=top_chunk_k_value, filter=metadata
        )
    else:
        documents = search_index.similarity_search(query=query, k=top_chunk_k_value)
    data = [
        {"chunk": document.page_content, "metadata": document.metadata}
        for document in documents
    ]
    return data


async def querying_with_r2r(query: str):
    data = {"query": query, "vector_search_settings": {}, "kg_search_settings": {}}
    response = requests.post(r2r_search_api_url, json=data)
    result = response.json()["results"]
    data = []
    for i in range(min(5, len(result["vector_search_results"]))):
        chunk = result["vector_search_results"][i]
        metadata = {
            "chunk_id": chunk["metadata"]["chunk_id"],
            "file_name": chunk["metadata"]["file_name"],
        }
        data.append({"chunk": chunk["metadata"]["text"], "metadata": metadata})
    return data


async def querying_with_hyde_pg_vector(
    collection_name: str, query: str, top_chunk_k_value: int = 5
):
    hyde_embeddings = HypotheticalDocumentEmbedder.from_llm(
        llm=OpenAI(), base_embeddings=embeddings, prompt_key="web_search"
    )
    pg_vector = PGVector(
        embeddings=hyde_embeddings,
        connection=db_url,
        collection_name=collection_name,
    )
    documents = pg_vector.similarity_search(query=query, k=top_chunk_k_value)
    data = [
        {"chunk": document.page_content, "metadata": document.metadata}
        for document in documents
    ]
    return data
