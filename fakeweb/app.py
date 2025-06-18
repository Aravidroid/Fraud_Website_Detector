import os
import socket
import ssl
import requests
import validators
import tldextract
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify, render_template
from playwright.sync_api import sync_playwright

# ----------- Flask App -----------
app = Flask(__name__)

# ----------- Ollama Config -----------
OLLAMA_API_URL = "http://localhost:11434/api/generate"  # Make sure Ollama is running locally
MODEL_NAME = "llama3"

# ----------- Routes -----------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/get_your_money_back')
def get_money_back():
    return render_template('money.html')

@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.get_json()
    url = data.get('url')

    if not validators.url(url):
        return jsonify({'error': 'Invalid URL'}), 400

    domain = url.replace("http://", "").replace("https://", "").split('/')[0]

    result = {
        'domain': domain
    }

    # DNS Lookup
    try:
        ip = socket.gethostbyname(domain)
        result['ip'] = ip
    except Exception:
        result['ip'] = None

    # SSL Certificate check
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3.0)
            s.connect((domain, 443))
            cert = s.getpeercert()
            result['ssl_valid'] = True
            result['cert_issuer'] = cert.get('issuer')
    except Exception:
        result['ssl_valid'] = False

    # HTTP Security Headers check
    try:
        resp = requests.get(url, timeout=5)
        headers = resp.headers
        missing_headers = []
        for h in ['X-Frame-Options', 'Content-Security-Policy', 'Strict-Transport-Security']:
            if h not in headers:
                missing_headers.append(h)
        result['missing_headers'] = missing_headers
    except Exception:
        result['missing_headers'] = ['Cannot connect']

    # Perform full scraping + LLM analysis
    try:
        text = scrape_multi_pages(url, max_pages=5)
        if text:
            domain_clean = tldextract.extract(url).registered_domain
            analysis = analyze_intent_llama(text, domain_clean)
            result['llm_analysis'] = analysis
        else:
            result['llm_analysis'] = 'Could not scrape site.'
    except Exception as e:
        result['llm_analysis'] = f'Error during analysis: {str(e)}'

    return jsonify(result)

# ----------- Scraper Logic -----------
def scrape_multi_pages(base_url, max_pages=5):
    print(f"Starting crawl: {base_url}")
    visited = set()
    to_visit = [base_url]
    collected_text = ""

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        while to_visit and len(visited) < max_pages:
            current_url = to_visit.pop(0)
            if current_url in visited:
                continue
            print(f"Scraping: {current_url}")
            try:
                page.goto(current_url, timeout=30000)
                html = page.content()
            except Exception as e:
                print("Failed to load:", e)
                continue

            visited.add(current_url)
            text = extract_text(html)
            collected_text += text + "\n"

            # Find internal links
            soup = BeautifulSoup(html, "html.parser")
            for link in soup.find_all("a", href=True):
                href = link['href']
                full_url = urljoin(base_url, href)
                if is_same_domain(base_url, full_url) and full_url not in visited:
                    to_visit.append(full_url)

        browser.close()

    return collected_text[:20000]  # Limit size

# ----------- Text Cleaning -----------
def extract_text(html):
    soup = BeautifulSoup(html, "html.parser")
    for script in soup(["script", "style", "nav", "header", "footer"]):
        script.decompose()
    text = soup.get_text(separator=" ", strip=True)
    return text

# ----------- Domain Check -----------
def is_same_domain(base, test_url):
    return urlparse(base).netloc == urlparse(test_url).netloc

# ----------- LLM Call -----------
def analyze_intent_llama(text, domain):
    prompt = f"""
You are a fraud detection expert.
Analyze the following website content and predict its intent:

Domain: {domain}
Content:
{text}

Answer these:
1. Is this site selling something? (Yes/No)
2. Is it making unrealistic claims? (Yes/No)
3. Is it impersonating a known brand? (Yes/No)
4. Scam risk level? (Low / Medium / High)
5. Explain your reasoning in 2-3 sentences.
"""

    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False
    }

    response = requests.post(OLLAMA_API_URL, json=payload)
    response.raise_for_status()
    output = response.json()
    return output["response"]

# ----------- Run App -----------
if __name__ == '__main__':
    app.run(debug=True)
