import requests
from transformers import pipeline
import re

# Load models for NER, threat classification, and summarization
ner_model = pipeline("ner", model="dslim/bert-base-NER")
classification_model = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")
summarizer = pipeline("summarization", model="facebook/bart-large-cnn")

# Extract IoCs from the given text
def extract_iocs(text):
    entities = ner_model(text)
    iocs = {"domains": [], "ips": [], "cves": []}
    
    for entity in entities:
        if entity['entity'] == 'DOMAIN':
            iocs['domains'].append(entity['word'])
        elif entity['entity'] == 'IP':
            iocs['ips'].append(entity['word'])
        elif entity['entity'] == 'CVE':
            iocs['cves'].append(entity['word'])
    
    return iocs

# Classify the type of threat
def classify_threat(text):
    labels = ["Phishing", "Malware", "Ransomware", "DDoS", "Data Breach", "Harmless"]
    result = classification_model(text, candidate_labels=labels)
    return result["labels"][0]

# Summarize the given text
def summarize_text(text):
    # Tokenize the text and check its length
    inputs = summarizer.tokenizer(text, return_tensors="pt", truncation=True, padding=True, max_length=1024)

    # Generate the summary
    summary = summarizer.model.generate(**inputs)
    summary_text = summarizer.tokenizer.decode(summary[0], skip_special_tokens=True)

    return summary_text

# Fetch content from a URL and analyze it
def fetch_and_analyze(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Will raise an HTTPError for bad responses (4xx, 5xx)
        
        text = response.text
        summary = summarize_text(text)
        iocs = extract_iocs(text)
        threat_label = classify_threat(text)
        
        return {
            "url": url,
            "summary": summary,
            "ioc_extracted": iocs,
            "threat_classification": threat_label,
            "final_verdict": "Harmful" if threat_label != "Harmless" else "Benign"
        }
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

if __name__ == "__main__":
    url = input("Paste the URL to analyze: ")
    result = fetch_and_analyze(url)
    
    if result:
        if "error" in result:
            print(f"Error fetching data: {result['error']}")
        else:
            print(f"Analysis Result:\n{result}")
    else:
        print("Failed to fetch or analyze the content.")
