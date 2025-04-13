import requests
from transformers import pipeline
import re

# Load models
ner_model = pipeline("ner", model="dslim/bert-base-NER")
classification_model = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")
summarizer = pipeline("summarization", model="facebook/bart-large-cnn")

def extract_iocs(text):
    domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    cve_pattern = r'\bCVE-\d{4}-\d{4,7}\b'
    return {
        "domains": re.findall(domain_pattern, text),
        "ips": re.findall(ip_pattern, text),
        "cves": re.findall(cve_pattern, text)
    }

def classify_threat(text):
    labels = ["Phishing", "Malware", "Ransomware", "DDoS", "Data Breach", "Harmless"]
    result = classification_model(text, candidate_labels=labels)
    return result["labels"][0]

def summarize_text(text):
    summary = summarizer(text, max_length=150, min_length=50, do_sample=False)
    return summary[0]['summary_text']

def fetch_and_analyze(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        text = response.text
        return {
            "url": url,
            "summary": summarize_text(text),
            "ioc_extracted": extract_iocs(text),
            "threat_classification": classify_threat(text),
            "final_verdict": "Harmful" if classify_threat(text) != "Harmless" else "Harmless"
        }
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

if _name_ == "_main_":
    url = input("Paste the URL to analyze: ")
    result = fetch_and_analyze(url)
    print(result if "error" not in result else f"Error: {result['error']}")