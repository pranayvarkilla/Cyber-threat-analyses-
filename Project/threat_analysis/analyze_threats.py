from transformers import pipeline

# NER Model
ner_model = pipeline("ner", model="dslim/bert-base-NER")

# Zero-shot classification instead of unavailable model
classification_model = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")

# Summarization model
summarization_model = pipeline("summarization", model="facebook/bart-large-mnli")

def extract_iocs(text):
    entities = ner_model(text)
    iocs = [entity["word"] for entity in entities if entity["entity"] in ["IP", "DOMAIN", "CVE"]]
    return iocs

def classify_threat(text):
    candidate_labels = ["Phishing", "Malware", "Ransomware", "DDoS", "Data Breach", "Benign"]
    result = classification_model(text, candidate_labels=candidate_labels)
    return result["labels"][0]

def summarize_text(text):
    summary = summarization_model(text, max_length=50, min_length=25, do_sample=False)
    return summary[0]["summary_text"]

if __name__ == "__main__":
    sample_text = "A new phishing campaign targeting banks has been detected. The attackers are using fake domains like example-fake.com."
    print("Extracted IoCs:", extract_iocs(sample_text))
    print("Threat Classification:", classify_threat(sample_text))
    print("Summary:", summarize_text(sample_text))
