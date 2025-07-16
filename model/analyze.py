import pickle
import os
from utils.scanner import scan_website
import numpy as np

# Load model and encoder
MODEL_PATH = os.path.join("model", "security_model.pkl")
ENCODER_PATH = os.path.join("model", "label_encoder.pkl")

with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

with open(ENCODER_PATH, "rb") as f:
    encoder = pickle.load(f)

def classify_manually(features):
    score = 0
    score += 2 if not features["SSL_valid"] else 0
    score += 2 if features["SSL_expiry_days"] < 30 else 0
    score += 1 if not features["HSTS"] else 0
    score += 1 if not features["X_Frame"] else 0
    score += 1 if not features["CSP"] else 0
    score += 1 if features["External_Scripts"] > 10 else 0
    score += 1 if features["Inline_JS"] else 0

    if score <= 1:
        return "Secure"
    elif score <= 3:
        return "Warning"
    else:
        return "High Risk"

def analyze_website(url):
    features = scan_website(url)
    if not features:
        return {"error": "Scan failed or website unreachable."}

    # Overriding model: classify manually
    label = classify_manually(features)

    # 🔍 Explanation based on features
    problems = []
    suggestions = []

    if not features["SSL_valid"]:
        problems.append("❌ SSL certificate is invalid or expired")
        suggestions.append("➡️ Renew and configure a valid SSL certificate")

    if features["SSL_expiry_days"] < 30:
        problems.append("⚠️ SSL certificate expires soon")
        suggestions.append("➡️ Renew your SSL certificate")

    if not features["HSTS"]:
        problems.append("⚠️ Missing HTTP Strict Transport Security (HSTS)")
        suggestions.append("➡️ Add HSTS header to enforce HTTPS")

    if not features["X_Frame"]:
        problems.append("⚠️ Missing X-Frame-Options header")
        suggestions.append("➡️ Add X-Frame-Options to prevent clickjacking")

    if not features["CSP"]:
        problems.append("⚠️ Missing Content Security Policy (CSP)")
        suggestions.append("➡️ Add a CSP header to protect against XSS")

    if features["External_Scripts"] > 10:
        problems.append(f"⚠️ High number of external scripts ({features['External_Scripts']})")
        suggestions.append("➡️ Reduce external JS to minimize attack surface")

    if features["Inline_JS"]:
        problems.append("⚠️ Inline JavaScript detected")
        suggestions.append("➡️ Move JS to external files and add CSP")

    return {
        "url": url,
        "prediction": label,
        "problems": problems if problems else ["✅ No major security issues detected."],
        "suggestions": suggestions if suggestions else ["🎉 Your website is well secured!"],
        "raw_features": features
    }
