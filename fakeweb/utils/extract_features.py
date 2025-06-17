import re
import socket
import ssl
import whois
from urllib.parse import urlparse
from datetime import datetime

def extract_features_from_url(url):
    features = {}

    # Ensure correct format
    if not url.startswith('http'):
        url = 'http://' + url

    parsed = urlparse(url)
    domain = parsed.netloc

    # Feature 1: URL length
    features['url_length'] = len(url)

    # Feature 2: Special characters in URL
    features['count_dots'] = url.count('.')
    features['count_hyphens'] = url.count('-')
    features['count_at'] = url.count('@')

    # Feature 3: Whois domain age
    try:
        w = whois.whois(domain)
        if isinstance(w.creation_date, list):
            creation = w.creation_date[0]
        else:
            creation = w.creation_date

        if isinstance(creation, datetime):
            age_days = (datetime.now() - creation).days
        else:
            age_days = -1

        features['domain_age_days'] = age_days
    except:
        features['domain_age_days'] = -1

    # Feature 4: SSL certificate presence
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                features['has_ssl'] = 1
    except:
        features['has_ssl'] = 0

    return features
