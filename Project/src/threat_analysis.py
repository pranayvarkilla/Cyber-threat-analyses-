# Importing the pipeline function from the Hugging Face Transformers library
from transformers import pipeline

# Initializing a text classification model using DistilBERT
classifier = pipeline("text-classification", model="distilbert-base-uncased")

# Function to classify the given threat description
def classify_threat(description):
    # Passing the input text to the classifier
    result = classifier(description)
    # Returning the predicted label (e.g., "positive", "negative", or a specific category)
    return result[0]['label']

# Main execution block to test the function
if __name__ == "__main__":
    # Example threat description to classify
    test_text = "A new ransomware attack is targeting healthcare institutions."
    # Printing the classification result
    print(classify_threat(test_text))
