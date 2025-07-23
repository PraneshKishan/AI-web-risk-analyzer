import requests
from urllib.parse import urlparse
import ssl
import socket
from datetime import datetime
from bs4 import BeautifulSoup

def get_ssl_details(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get('notAfter')
                expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                days_left = (expiry_date - datetime.utcnow()).days
                return 1, max(days_left, 0)
    except:
        return 0, 0  # Invalid or unreachable

def scan_website(url):
    features = {
        "SSL_valid": 0,
        "SSL_expiry_days": 0,
        "HTTPS": 0,
        "HSTS": 0,
        "X_Frame": 0,
        "CSP": 0,
        "Script_Count": 0,
        "External_Scripts": 0,
        "Inline_JS": 0
    }

    headers = {
        "User-Agent": "Mozilla/5.0"
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        features["HTTPS"] = 1 if url.startswith("https") else 0

        # Headers
        features["HSTS"] = int("Strict-Transport-Security" in response.headers)
        features["X_Frame"] = int("X-Frame-Options" in response.headers)
        features["CSP"] = int("Content-Security-Policy" in response.headers)

        # Script analysis
        soup = BeautifulSoup(response.text, "html.parser")
        scripts = soup.find_all("script")
        features["Script_Count"] = len(scripts)
        features["External_Scripts"] = sum(1 for s in scripts if s.get("src") and s["src"].startswith("http"))
        features["Inline_JS"] = sum(1 for s in scripts if s.string and "alert(" in s.string)

        # SSL details
        domain = urlparse(url).hostname
        features["SSL_valid"], features["SSL_expiry_days"] = get_ssl_details(domain)

    except Exception as e:
        # If the website is unreachable, return default values (all zeros)
        return features  # Still return zeros so ML model can classify

    return features
