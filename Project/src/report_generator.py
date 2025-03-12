from transformers import pipeline

summarizer = pipeline("summarization", model="facebook/bart-large-cnn")

def generate_report(text):
    summary = summarizer(text, max_length=100, min_length=30, do_sample=False)
    return summary[0]['summary_text']

if __name__ == "__main__":
    threat_data = "Cybercriminals have launched a massive phishing campaign targeting financial institutions."
    print(generate_report(threat_data))
