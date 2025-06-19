import re
import socket
import ssl
import requests
import validators
import tldextract
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify, render_template
from playwright.sync_api import sync_playwright
import datetime
from datetime import timezone
import OpenSSL

app = Flask(__name__)

OLLAMA_API_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "HammerAI/openhermes-2.5-mistral"

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
    result = {'domain': domain}

    try:
        ip = socket.gethostbyname(domain)
        result['ip'] = ip
    except Exception as e:
        ip = None
        result['ip'] = None
        result['ip_error'] = str(e)

    try:
        if ip:
            hostname, _, _ = socket.gethostbyaddr(ip)
            result['reverse_dns'] = hostname
        else:
            result['reverse_dns'] = 'Unavailable'
    except Exception as e:
        result['reverse_dns'] = 'Failed'
        result['reverse_dns_error'] = str(e)

    try:
        if ip:
            from ipwhois import IPWhois
            ipwhois_data = IPWhois(ip).lookup_rdap()
            result['asn'] = ipwhois_data.get('asn', 'Unknown')
            result['asn_description'] = ipwhois_data.get('asn_description', 'Unknown')
            result['isp_org'] = ipwhois_data.get('network', {}).get('name', 'Unknown')
            result['country'] = ipwhois_data.get('network', {}).get('country') or ipwhois_data.get('asn_country_code', 'Unknown')
        else:
            result.update({
                'asn': 'Unavailable',
                'asn_description': 'Unavailable',
                'isp_org': 'Unavailable',
                'country': 'Unavailable'
            })
    except Exception as e:
        result['ipwhois_error'] = str(e)

    result.update(get_ssl_info(domain))

    try:
        resp = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
        headers = resp.headers
        missing_headers = []
        for h in ['X-Frame-Options', 'Content-Security-Policy', 'Strict-Transport-Security']:
            if h not in headers:
                missing_headers.append(h)
        result['missing_headers'] = missing_headers
    except Exception:
        result['missing_headers'] = ['Cannot connect']

    import whois
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        result['domain_creation_date'] = creation_date.strftime('%Y-%m-%d')
        result['domain_age_days'] = (datetime.datetime.now() - creation_date).days
        result['domain_registrar'] = domain_info.registrar or 'Unknown'
        result['domain_owner'] = domain_info.org or 'Not available'
    except Exception as e:
        result['domain_creation_date'] = 'Unavailable'
        result['domain_age_days'] = 'Unknown'
        result['domain_registrar'] = 'Unavailable'
        result['domain_owner'] = 'Unavailable'
        result['whois_error'] = str(e)

    try:
        text = scrape_multi_pages(url, max_pages=5)
        if text:
            ext = tldextract.extract(url)
            domain_clean = f"{ext.domain}.{ext.suffix}"
            llm = analyze_intent_llama(text, domain_clean)
            if isinstance(llm, dict):
                result.update(llm)

                trust_raw = llm.get("question_7", "")
                match = re.search(r'(\d+)', trust_raw)
                trustscore = int(match.group(1)) if match else "N/A"

                result['trustscore'] = trustscore
                result['risk_level'] = llm.get("question_5", "Unknown")
                result['summary'] = llm.get("question_8", "N/A")

                summary_paragraph = f"""
1. {llm.get("question_1", "N/A")}
2. {llm.get("question_2", "N/A")}
3. {llm.get("question_3", "N/A")}
4. {llm.get("question_4", "N/A")}
5. Scam Risk: {llm.get("question_5", "N/A")}
6. Reasoning: {llm.get("question_6", "N/A")}
7. Trust Score: {llm.get("question_7", "N/A")} stars
8. Summary: {llm.get("question_8", "N/A")}
""".replace("\n", " ").strip()

                result['llm_summary'] = summary_paragraph
            else:
                result['llm_analysis'] = llm
        else:
            result['llm_analysis'] = 'Could not scrape site.'
    except Exception as e:
        result['llm_analysis'] = f'Error during analysis: {str(e)}'

    return jsonify(result)

def get_ssl_info(domain):
    try:
        pem_cert = ssl.get_server_certificate((domain, 443))
        print("Fetched SSL cert:\n", pem_cert[:100] + '...')
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_cert)

        issuer = x509.get_issuer()
        subject = x509.get_subject()
        not_after = x509.get_notAfter().decode('ascii')
        expiry_date = datetime.datetime.strptime(not_after, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)

        return {
            'ssl_valid': True,
            'cert_expiry': expiry_date.strftime('%Y-%m-%d'),
            'cert_days_remaining': (expiry_date - datetime.datetime.now(timezone.utc)).days,
            'cert_subject': {k: getattr(subject, k) for k in dir(subject) if not k.startswith('_') and isinstance(getattr(subject, k), str)},
            'cert_issuer': {k: getattr(issuer, k) for k in dir(issuer) if not k.startswith('_') and isinstance(getattr(issuer, k), str)}
        }
    except Exception as e:
        print("SSL Error:", str(e))
        return {
            'ssl_valid': False,
            'ssl_expiry': "N/A",
            'ssl_error': str(e)
        }

def extract_text(html):
    soup = BeautifulSoup(html, "html.parser")
    for script in soup(["script", "style", "nav", "header", "footer"]):
        script.decompose()
    return soup.get_text(separator=" ", strip=True)

def scrape_multi_pages(base_url, max_pages=5):
    collected_text = ""
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(base_url, timeout=10000)
            html = page.content()
            collected_text += extract_text(html)

            soup = BeautifulSoup(html, "html.parser")
            links = soup.find_all('a', href=True)
            base_domain = urlparse(base_url).netloc
            internal_links = set()

            for link in links:
                href = link['href']
                full_url = urljoin(base_url, href)
                parsed = urlparse(full_url)
                if parsed.netloc == base_domain:
                    internal_links.add(full_url)
                if len(internal_links) >= max_pages - 1:
                    break

            for link in internal_links:
                try:
                    page.goto(link, timeout=10000)
                    html = page.content()
                    collected_text += "\n" + extract_text(html)
                except Exception:
                    continue

            browser.close()
    except Exception as e:
        print("Scraping Error:", e)

    return collected_text.strip()

def analyze_intent_llama(text, domain):
    prompt = f"""
Analyze the website content from domain '{domain}' and answer the following 8 questions:
1. What is the website offering?
2. Are there any signs that indicate it may be a scam?
3. How trustworthy does the site appear based on language, offers, and structure?
4. Are there any red flags in the site's content or claims?
5. What is the scam risk level (High, Medium, Low)?
6. Why do you say it’s a scam or not?
7. Rate this site from 1 to 5 based on trustworthiness.
8. Give 3 lines about the website and its potential risk.

Website Text:
{text[:7000]}
"""
    try:
        response = requests.post(
            OLLAMA_API_URL,
            json={"model": MODEL_NAME, "prompt": prompt, "stream": False}
        )
        if response.status_code == 200:
            content = response.json().get("response", "")
            return parse_llm_answers(content)
        else:
            return {"llm_error": f"Ollama error: {response.text}"}
    except Exception as e:
        return {"llm_error": str(e)}

def parse_llm_answers(response_text):
    output = {}
    for i in range(1, 9):
        match = re.search(rf"{i}\.\s*(.*?)\s*(?=\n\d\.|$)", response_text, re.DOTALL)
        if match:
            output[f"question_{i}"] = match.group(1).strip()
        else:
            output[f"question_{i}"] = "N/A"
    output["llm_output"] = response_text.strip()
    return output

if __name__ == '__main__':
    app.run(debug=True)
