import requests
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

# Analyze fetched data
def analyze_text(text):
    # Extract IoCs
    iocs = extract_iocs(text)
    print("Extracted IoCs:", iocs)
    
    # Classify threat
    threat = classify_threat(text)
    print("Threat Type:", threat)
    
    # Summarize text
    summary = summarize_text(text)
    print("Summary:", summary)

if __name__ == "__main__":
    url = "https://www.cisa.gov/news-events/news"  # You can change the URL
    text = fetch_data_from_url(url)
    
    if text:
        analyze_text(text)
    else:
        print("Failed to fetch data from the URL.")
