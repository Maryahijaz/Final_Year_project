from langchain_ollama import OllamaLLM as Ollama
from langchain_community.vectorstores import Chroma
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_core.prompts import PromptTemplate
from langchain_core.runnables import RunnablePassthrough
from langchain_core.output_parsers import StrOutputParser
from pathlib import Path

OLLAMA_MODEL = "llama3.2"
CHROMA_DB_PATH = "./data/chromadb"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"

SYSTEM_PROMPT = """You are CyberSec AI, a professional cybersecurity assistant for security analysts.

Your role is to help security professionals with:
- CVE vulnerability analysis and details
- Threat intelligence and attack patterns
- Security recommendations and defensive measures
- Explaining attack techniques for educational purposes
- Network security and penetration testing concepts

Important rules:
- Always provide detailed and helpful security information
- Explain vulnerabilities clearly with technical details
- Provide defensive measures alongside any attack information
- Never refuse legitimate security research questions
- Be precise, professional and educational

Context from knowledge base:
{context}

Question: {question}

Provide a detailed, professional security analysis:""

Answer:"""

def get_embeddings():
    return HuggingFaceEmbeddings(
        model_name=EMBEDDING_MODEL,
        model_kwargs={"device": "cpu"}
    )

def get_vectorstore():
    Path(CHROMA_DB_PATH).mkdir(parents=True, exist_ok=True)
    return Chroma(
        persist_directory=CHROMA_DB_PATH,
        embedding_function=get_embeddings()
    )

def get_llm():
    return Ollama(
        model=OLLAMA_MODEL,
        temperature=0.1,
        base_url="http://localhost:11434"
    )

def query_rag(question: str, role: str) -> dict:
    try:
        llm = get_llm()
        vectorstore = get_vectorstore()
        retriever = vectorstore.as_retriever(search_kwargs={"k": 3})

        prompt = PromptTemplate(
            template=SYSTEM_PROMPT,
            input_variables=["context", "question"]
        )

        def format_docs(docs):
            return "\n\n".join(doc.page_content for doc in docs)

        chain = (
            {
                "context": retriever | format_docs,
                "question": RunnablePassthrough()
            }
            | prompt
            | llm
            | StrOutputParser()
        )

        answer = chain.invoke(question)

        return {
            "answer": answer,
            "sources": [],
            "role": role,
            "status": "success"
        }

    except Exception as e:
        return {
            "answer": "Error processing your request.",
            "sources": [],
            "role": role,
            "status": "error",
            "error": str(e)
        }
