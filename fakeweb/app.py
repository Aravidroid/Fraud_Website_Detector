import re
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
import datetime
from datetime import timezone
import OpenSSL
import json
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG)

OLLAMA_API_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "gemma3:4b"

class FeatureExtraction:
    def __init__(self, url):
        self.url = url
        self.urlparse = urlparse(url)
        self.domain = self.urlparse.netloc
        self.response = None
        self.soup = None
        try:
            self.response = requests.get(url, timeout=5)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except requests.exceptions.RequestException:
            pass

    def getFeaturesDict(self):
        try:
            return {
                "UsingIp": validators.ipv4(self.domain) or validators.ipv6(self.domain),
                "LongURLLength": len(self.url),
                "ShortenerUsed": any(short in self.url for short in [
                    'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co', 'bit.do', 'adf.ly'
                ]),
                "HasAtSymbol": '@' in self.url,
                "DoubleSlashRedirect": self.url.rfind('//') > 6,
                "PrefixSuffixInDomain": '-' in self.domain,
                "SubdomainCount": self.domain.count('.'),
                "UsesHTTPS": self.url.startswith('https'),
                "HasFavicon": any('favicon' in link['href'].lower() for link in self.soup.find_all('link', href=True)) if self.soup else False,
                "NonStandardPort": ':' in self.urlparse.netloc and not self.url.startswith("https://"),
                "HTTPSInDomain": 'https' in self.domain.lower(),
                "FormWithBlankAction": any(form['action'] in ["", "about:blank"] for form in self.soup.find_all('form', action=True)) if self.soup else False,
                "RightClickDisabled": bool(re.search("event.button ?== ?2", self.response.text)) if self.response else False,
                "HasPopup": bool(re.search(r"alert\\(", self.response.text)) if self.response else False,
                "HasIframe": bool(self.soup.find_all('iframe')) if self.soup else False,
                "CountExternalLinks": sum(1 for a in self.soup.find_all('a', href=True) if self.domain not in a['href']) if self.soup else 0
            }
        except Exception as e:
            return {"feature_extraction_error": str(e)}

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

        llm_input = {
            "domain": domain,
            "ip": ip,
            "reverse_dns": result.get("reverse_dns"),
            "asn": result.get("asn"),
            "asn_description": result.get("asn_description"),
            "isp_org": result.get("isp_org"),
            "country": result.get("country"),
            "ssl_valid": result.get("ssl_valid"),
            "cert_expiry": result.get("cert_expiry"),
            "cert_days_remaining": result.get("cert_days_remaining"),
            "missing_headers": result.get("missing_headers"),
            "domain_creation_date": result.get("domain_creation_date"),
            "domain_age_days": result.get("domain_age_days"),
            "domain_registrar": result.get("domain_registrar"),
            "domain_owner": result.get("domain_owner"),
            "heuristics": FeatureExtraction(url).getFeaturesDict(),
            "text_content": text[:5000]
        }

        llm = analyze_intent_llama(llm_input)
        if isinstance(llm, dict):
            result.update(llm)

            trust_raw = llm.get("question_6", "")
            match = re.search(r'(\d+)', trust_raw)
            trustscore = int(match.group(1)) if match else "N/A"
            result['trustscore'] = trustscore
            result['risk_level'] = llm.get("question_5", "Unknown")
            result['summary'] = llm.get("question_7", "N/A")

            summary_paragraph = f"""
1. {llm.get("question_1", "N/A")}
2. {llm.get("question_2", "N/A")}
3. {llm.get("question_3", "N/A")}
4. {llm.get("question_4", "N/A")}
5. Scam Risk: {llm.get("question_5", "N/A")}
6. Trust Score: {llm.get("question_6", "N/A")} stars
7. Summary: {llm.get("question_7", "N/A")}
""".replace("\n", " ").strip()

        else:
            result['llm_analysis'] = llm
    except Exception as e:
        result['llm_analysis'] = f'Error during analysis: {str(e)}'

    try:
        os.makedirs("scan_results", exist_ok=True)
        final_filename = os.path.join("scan_results", f"{domain.replace('.', '_')}_report.txt")
        with open(final_filename, "w", encoding="utf-8") as f:
            for key, value in result.items():
                f.write(f"{key}: {value}\n")
        result['report_file'] = final_filename
    except Exception as e:
        result['report_save_error'] = str(e)

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

def scrape_multi_pages(base_url, max_pages=3):
    print(f"\n Starting to scrape: {base_url}")
    collected_text = ""
    filename = None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(base_url, timeout=10000, wait_until='domcontentloaded')
            html = page.content()
            collected_text += extract_text(html)

            soup = BeautifulSoup(html, "html.parser")
            links = soup.find_all('a', href=True)
            base_domain = urlparse(base_url).netloc
            domain_clean = base_domain.replace("www.", "").replace(":", "_")
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
                    print(f"Visiting: {link}")
                    page.goto(link, timeout=10000, wait_until='domcontentloaded')
                    html = page.content()
                    collected_text += "\n" + extract_text(html)
                except Exception:
                    continue
            browser.close()
        
            os.makedirs("scraped_sites", exist_ok=True)
            filename = os.path.join("scraped_sites", f"{domain_clean}.txt")
            with open(filename, "w", encoding="utf-8") as f:
                f.write(collected_text.strip())
            print(f"Scraped content saved to {filename}")
            
    except Exception as e:
        print("Scraping Error:", e)

    return collected_text.strip()

def analyze_intent_llama(llm_input):
    tech_info = f"""
DOMAIN INFORMATION:
- Domain: {llm_input['domain']}
- IP: {llm_input['ip']}
- Reverse DNS: {llm_input['reverse_dns']}
- ASN: {llm_input['asn']} ({llm_input['asn_description']})
- ISP/Org: {llm_input['isp_org']}
- Country: {llm_input['country']}

WHOIS INFO:
- Creation Date: {llm_input['domain_creation_date']}
- Domain Age (days): {llm_input['domain_age_days']}
- Registrar: {llm_input['domain_registrar']}
- Owner: {llm_input['domain_owner']}

SSL CERTIFICATE:
- Valid: {llm_input['ssl_valid']}
- Expiry: {llm_input['cert_expiry']}
- Days Remaining: {llm_input['cert_days_remaining']}

SECURITY HEADERS:
- Missing Headers: {', '.join(llm_input['missing_headers'])}

FEATURE HEURISTICS:
- {json.dumps(llm_input['heuristics'], indent=2)}
"""

    prompt = f"""
Based on the following technical data and website content, evaluate whether the site is trustworthy or potentially a scam.

{tech_info}

SCRAPED WEBSITE TEXT:
{llm_input['text_content']}

Answer the following questions:
1. What does this site appear to offer?
2. Are there technical red flags (SSL, Whois, IP, headers)?
3. Are there content-based scam indicators (language, layout, urgency)?
4. Are heuristic flags like popups, iframes, IP usage, or shorteners present?
5. Overall, is this site safe or suspicious?
6. Give a trustworthiness score out of 5 and justify it.
7. Summarize in 3 lines what a user should know before trusting this site.
"""
    try:
        logging.debug("\n=== SENDING PROMPT TO OLLAMA ===")
        logging.debug(prompt[:1000] + '... [truncated]' if len(prompt) > 1000 else prompt)
        response = requests.post(
            OLLAMA_API_URL,
            json={"model": MODEL_NAME, "prompt": prompt, "stream": False}
        )
        print(f"\n=== OLLAMA RESPONSE STATUS: {response.status_code} ===")
        if response.status_code == 200:
            content = response.json().get("response", "")
            print("\n Raw LLM Response:")
            print(content.strip())
            return parse_llm_answers(content)
        else:
            print("\n=== OLLAMA ERROR RESPONSE ===")
            print(response.text)
            return {"llm_error": f"Ollama error: {response.text}"}
    except Exception as e:
        print("\n=== EXCEPTION TALKING TO OLLAMA ===")
        print(str(e))
        return {"llm_error": str(e)}

def parse_llm_answers(response_text):
    print("Parsing LLM Response:")
    output = {}
    for i in range(1, 9):
        match = re.search(rf"{i}\.\\s*(.*?)\\s*(?=\\n\\d\\.|$)", response_text, re.DOTALL)
        if match:
            output[f"question_{i}"] = match.group(1).strip()
        else:
            output[f"question_{i}"] = "N/A"

    output["llm_output"] = response_text.strip()
    return output

if __name__ == '__main__':
    app.run(debug=True)
