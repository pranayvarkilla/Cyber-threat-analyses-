# Import FastAPI framework to create a web API
from fastapi import FastAPI  

# Import the threat classification function from the threat analysis module
from src.threat_analysis import classify_threat  

# Import the report generation function from the report generator module
from src.report_generator import generate_report  

# Create a FastAPI app instance
app = FastAPI()

# Define a POST endpoint at "/analyze/" to analyze cybersecurity threats
@app.post("/analyze/")
async def analyze_threat(description: str):
    # Classify the threat based on the provided description
    category = classify_threat(description)
    
    # Generate a summary report for the given threat description
    summary = generate_report(description)
    
    # Return the threat category and generated summary as JSON response
    return {"category": category, "summary": summary}
