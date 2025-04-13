

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import requests
import re
import os
from transformers import pipeline, BartTokenizer, BartForConditionalGeneration

# Load pre-trained models
print("Loading models...")
ner_model = pipeline("ner", model="dslim/bert-base-NER")
classification_model = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")
tokenizer = BartTokenizer.from_pretrained('facebook/bart-large-cnn')
summarization_model = BartForConditionalGeneration.from_pretrained('facebook/bart-large-cnn')
print("Models loaded successfully.")

# FastAPI app
app = FastAPI()

# Input model
class URLInput(BaseModel):
    url: str

# --- Analysis Logic ---
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
    inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=1024, padding="max_length")
    summary_ids = summarization_model.generate(inputs["input_ids"], max_length=50, min_length=25, do_sample=False)
    return tokenizer.decode(summary_ids[0], skip_special_tokens=True)

def fetch_and_analyze(url):
    try:
        print(f"Fetching content from URL: {url}")
        response = requests.get(url)
        response.raise_for_status()
        text = response.text

        print("Extracting IoCs...")
        iocs = extract_iocs(text)

        print("Classifying threat...")
        threat = classify_threat(text)

        print("Summarizing text...")
        summary = summarize_text(text)

        print("Analysis complete.")
        return {
            "url": url,
            "summary": summary,
            "ioc_extracted": iocs,
            "threat_classification": threat,
            "final_verdict": "Harmful" if threat != "Harmless" else "Harmless"
        }

    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Error fetching URL: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis error: {str(e)}")

# --- API Endpoint ---
@app.post("/analyze-url")
async def analyze_url(input: URLInput):
    return fetch_and_analyze(input.url)

# --- Serve Frontend ---
frontend_path = os.path.join(os.path.dirname(_file_), "../frontend")
app.mount("/static", StaticFiles(directory=frontend_path), name="static")

@app.get("/")
async def root():
    return FileResponse(os.path.join(frontend_path, "index.html"))