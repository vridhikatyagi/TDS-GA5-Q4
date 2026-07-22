from flask import Flask, request, jsonify
from scanner import scan_skill

app = Flask(__name__)

@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

@app.route("/", methods=["POST"])
@app.route("/scan", methods=["POST"])
def scan():
    try:
        data = request.get_json(force=True, silent=True) or {}
        skill_text = data.get("skill", "") or ""
        if not isinstance(skill_text, str):
            skill_text = str(skill_text)
        categories = scan_skill(skill_text)
    except Exception:
        categories = []
    return jsonify({"categories": categories})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
