from transformers import pipeline

# Load models for NER, threat classification, and summarization
ner_model = pipeline("ner", model="dslim/bert-base-NER")
classification_model = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")
summarizer = pipeline("summarization", model="facebook/bart-large-cnn")

# Extract IoCs from the text
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

# Classify the threat type
def classify_threat(text):
    labels = ["Phishing", "Malware", "Ransomware", "DDoS", "Data Breach", "Harmless"]
    result = classification_model(text, candidate_labels=labels)
    return result["labels"][0]

# Summarize the text
def summarize_text(text):
    summary = summarizer(text, max_length=150, min_length=50, do_sample=False)
    return summary[0]['summary_text']

# Analyze the URL content and text
def analyze_threat(url, text):
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

if __name__ == "__main__":
    url = input("Paste the URL to analyze: ")
    content = input("Paste the content to analyze: ")
    result = analyze_threat(url, content)
    print(f"Analysis Result:\n{result}")
