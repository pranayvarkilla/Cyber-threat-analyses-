from transformers import pipeline

classifier = pipeline("text-classification", model="distilbert-base-uncased")

def classify_threat(description):
    result = classifier(description)
    return result[0]['label']

if __name__ == "__main__":
    test_text = "A new ransomware attack is targeting healthcare institutions."
    print(classify_threat(test_text))
