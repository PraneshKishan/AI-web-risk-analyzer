from flask import Flask, request, jsonify, render_template
from model.analyze import analyze_website
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Enables CORS for frontend integration

# Serve the HTML frontend
@app.route("/")
def home():
    return render_template("index.html")

# Analyze endpoint (used by frontend JS)
@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "URL is required."}), 400

    try:
        result = analyze_website(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
