import requests
from bs4 import BeautifulSoup
import json

def fetch_cybersecurity_news():
    url = "https://www.cisa.gov/news-events/news"  # Replace with a real cybersecurity blog
    response = requests.get(url)
    soup = BeautifulSoup(response.content, "html.parser")
    
    articles = []
    for item in soup.find_all("div", class_="article"):  # Adjust based on the blog's HTML structure
        title = item.find("h2").text
        content = item.find("p").text
        articles.append({"title": title, "content": content})
    
    return articles

def save_data(data, filename="cyber_threats.json"):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

if __name__ == "__main__":
    news_data = fetch_cybersecurity_news()
    save_data(news_data)
    print("Data fetched and saved to cyber_threats.json")