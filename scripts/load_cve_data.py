import requests
import json
from pathlib import Path
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_core.documents import Document

CHROMA_DB_PATH = "./data/chromadb"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def get_embeddings():
    return HuggingFaceEmbeddings(
        model_name="/home/trustzai/trustzai/models/all-MiniLM-L6-v2",
        model_kwargs={"device": "cpu"}
    )

def fetch_cves(keywords: str = "remote code execution", results_per_page: int = 20):
    """
    يجلب CVEs من NVD API
    """
    print(f"Fetching CVEs for: {keywords}")
    params = {
        "keywordSearch": keywords,
        "resultsPerPage": results_per_page
    }
    response = requests.get(NVD_API_URL, params=params, timeout=30)
    if response.status_code != 200:
        print(f"Error: {response.status_code}")
        return []

    data = response.json()
    cves = data.get("vulnerabilities", [])
    print(f"Found {len(cves)} CVEs")
    return cves

def parse_cve(cve_item: dict) -> Document:
    """
    يحوّل CVE item لـ Document
    """
    cve = cve_item.get("cve", {})
    cve_id = cve.get("id", "Unknown")

    # الوصف
    descriptions = cve.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d["lang"] == "en"),
        "No description available"
    )

    # CVSS Score
    metrics = cve.get("metrics", {})
    cvss_score = "N/A"
    severity = "N/A"

    if "cvssMetricV31" in metrics:
        cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
        cvss_score = cvss_data.get("baseScore", "N/A")
        severity = cvss_data.get("baseSeverity", "N/A")
    elif "cvssMetricV2" in metrics:
        cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
        cvss_score = cvss_data.get("baseScore", "N/A")

    # Published date
    published = cve.get("published", "Unknown")[:10]

    content = f"""
CVE ID: {cve_id}
Published: {published}
CVSS Score: {cvss_score}
Severity: {severity}
Description: {description}
    """.strip()

    return Document(
        page_content=content,
        metadata={
            "source": "NVD",
            "cve_id": cve_id,
            "cvss_score": str(cvss_score),
            "severity": severity,
            "published": published
        }
    )

def load_to_chromadb(documents: list):
    """
    يحمّل الـ Documents في ChromaDB
    """
    print(f"Loading {len(documents)} documents to ChromaDB...")
    Path(CHROMA_DB_PATH).mkdir(parents=True, exist_ok=True)

    embeddings = get_embeddings()
    vectorstore = Chroma(
        persist_directory=CHROMA_DB_PATH,
        embedding_function=embeddings
    )

    vectorstore.add_documents(documents)
    print(f"✅ Successfully loaded {len(documents)} CVEs to ChromaDB")

def main():
    # جلب CVEs لعدة فئات
    keywords_list = [
        "remote code execution",
        "SQL injection",
        "buffer overflow",
        "privilege escalation",
        "cross site scripting"
    ]

    all_documents = []

    for keywords in keywords_list:
        cves = fetch_cves(keywords, results_per_page=10)
        for cve_item in cves:
            doc = parse_cve(cve_item)
            all_documents.append(doc)

    if all_documents:
        load_to_chromadb(all_documents)
        print(f"\n✅ Total CVEs loaded: {len(all_documents)}")
    else:
        print("❌ No CVEs fetched")

if __name__ == "__main__":
    main()
