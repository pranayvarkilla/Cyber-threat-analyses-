from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from transformers import pipeline

# NER Model
ner_model = pipeline("ner", model="dslim/bert-base-NER")

# Zero-shot classification instead of unavailable model
classification_model = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")

# Summarization model
summarization_model = pipeline("summarization", model="facebook/bart-large-mnli")

# Function Definitions
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
async def classify_threat(input: TextInput):
    try:
        threat_type = classify_threat(input.text)
        return {"threat_type": threat_type}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/summarize")
async def summarize(input: TextInput):
    try:
        summary = summarize_text(input.text)
        return {"summary": summary}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
