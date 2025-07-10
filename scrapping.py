"""
Simple Website Scraper

Features:
- Fetches a web page and extracts article titles and links.
- Saves results to 'output.csv'.
- Handles errors and uses polite headers.

Dependencies:
- requests
- beautifulsoup4

Install with:
    pip install requests beautifulsoup4
"""

import requests
from bs4 import BeautifulSoup
import csv
import time

def scrape_titles_and_links(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; SimpleScraper/1.0; +https://example.com/bot)"
    }
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
    except Exception as e:
        print(f"Error fetching the page: {e}")
        return []

    soup = BeautifulSoup(response.text, 'html.parser')
    results = []
    # Adjust selectors as needed for your target site:
    for a in soup.find_all('a', href=True):
        title = a.get_text(strip=True)
        link = a['href']
        if title and link:
            results.append({'title': title, 'link': link})
    return results

def save_to_log(data, filename="out-scrapper.log"):
    with open(filename, 'w', encoding='utf-8') as f:
        for item in data:
            f.write(f"Title: {item['title']}\nLink: {item['link']}\n\n")
    print(f"Saved {len(data)} records to {filename}")

def main():
    print("=== Simple Website Scraper ===")
    url = input("Enter the URL to scrape: ").strip()
    print("Scraping, please wait...")
    scraped = scrape_titles_and_links(url)
    if scraped:
        save_to_log(scraped)
    else:
        print("No data found or failed to scrape.")

if __name__ == "__main__":
    main()