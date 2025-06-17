# app.py
from flask import Flask, request, jsonify, render_template
import socket
import ssl
import requests
import validators

app = Flask(__name__)

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
        'domain': domain,
        'trustscore': 1,
        'scam_detected': True,
        'violations': ['Intellectual property violation detected (example)'],
        'feelings': {
            'angry': 64,
            'unhappy': 2,
            'neutral': 0,
            'happy': 3,
            'very_happy': 100
        },
        'reviews': 227,
        'rating': 2.8
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

    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
