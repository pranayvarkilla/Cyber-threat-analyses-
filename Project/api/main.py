import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from transformers import pipeline, BartTokenizer, BartForConditionalGeneration
import re

# Load pre-trained models for NER, classification, and summarization
ner_model = pipeline("ner", model="dslim/bert-base-NER")
classification_model = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")

# Load tokenizer and model for summarization
tokenizer = BartTokenizer.from_pretrained('facebook/bart-large-cnn')
summarization_model = BartForConditionalGeneration.from_pretrained('facebook/bart-large-cnn')

# Function to extract IoCs (Indicators of Compromise)
def extract_iocs(text):
    # Regular expressions for domains, IPs, and CVEs
    domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    cve_pattern = r'\bCVE-\d{4}-\d{4,7}\b'
    
    domains = re.findall(domain_pattern, text)
    ips = re.findall(ip_pattern, text)
    cves = re.findall(cve_pattern, text)

    return {
        "domains": domains,
        "ips": ips,
        "cves": cves
    }

# Function to classify the type of threat
def classify_threat(text):
    labels = ["Phishing", "Malware", "Ransomware", "DDoS", "Data Breach", "Harmless"]
    result = classification_model(text, candidate_labels=labels)
    return result["labels"][0]

# Function to summarize a given text
def summarize_text(text):
    # Tokenize and truncate the text if it's too long
    inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=1024, padding="longest")

    # Generate the summary
    summary_ids = summarization_model.generate(inputs["input_ids"], max_length=50, min_length=25, do_sample=False)

    # Decode the summary and return it
    summary = tokenizer.decode(summary_ids[0], skip_special_tokens=True)
    return summary

# FastAPI Setup
app = FastAPI()

class TextInput(BaseModel):
    text: str

@app.post("/detect-iocs")
async def detect_iocs(input: TextInput):
    try:
        iocs = extract_iocs(input.text)
        return {"iocs": iocs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/classify-threat")
async def classify_threat_endpoint(input: TextInput):
    try:
        threat = classify_threat(input.text)
        return {"threat_type": threat}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/summarize")
async def summarize(input: TextInput):
    try:
        summary = summarize_text(input.text)
        return {"summary": summary}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Fetch and analyze content from a URL
def fetch_data_from_url(url):
    response = requests.get(url)
    if response.status_code == 200:
        text = response.text
        return text
    return None

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
