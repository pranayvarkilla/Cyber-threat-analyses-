from fastapi import FastAPI
from src.threat_analysis import classify_threat
from src.report_generator import generate_report

app = FastAPI()

@app.post("/analyze/")
async def analyze_threat(description: str):
    category = classify_threat(description)
    summary = generate_report(description)
    return {"category": category, "summary": summary}
