from langchain_huggingface import HuggingFaceEmbeddings

EMBEDDING_MODEL = "all-MiniLM-L6-v2"

def get_embeddings():
    return HuggingFaceEmbeddings(
        model_name="/home/trustzai/trustzai/models/all-MiniLM-L6-v2",
        model_kwargs={"device": "cpu"}
    )
