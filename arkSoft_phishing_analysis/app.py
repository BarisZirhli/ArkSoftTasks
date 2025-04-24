from flask import Flask, jsonify, request
import phishing_analyze

app = Flask(__name__)


@app.route("/phishing", methods=["POST"])
def phishing_analysis_post():
    data = request.get_json()
    print(f"these data:{data}")
    if not data:
        return jsonify({"error": "HTML içeriği sağlanmadı."}), 400
    html_content = data.get("html_content", "empty")
    print(f"these html_content:{html_content}")

    if not html_content:
        return jsonify({"error": "HTML içeriği sağlanmadı."}), 400

    risk_details = phishing_analyze.analyze_turkish_html_phishing(html_content)
    risk_level = phishing_analyze.classify_phishing_risk(risk_details)
    print(f"these risk details:{risk_details}")
    return jsonify(
        {
            "risk_score": risk_details,
            "risk_level": risk_level,
        }
    )


@app.route("/phishing", methods=["GET"])
def phishing_analysis_get():
    data = request.args.get("html_content", "")

    if not data:
        return jsonify({"error": "HTML içeriği sağlanmadı."}), 400

    risk_details = phishing_analyze.analyze_turkish_html_phishing(data)
    risk_level = phishing_analyze.classify_phishing_risk(risk_details)

    return jsonify(
        {
            "risk_score": risk_details["total_score"],
            "risk_details": risk_details, 
            "risk_level": risk_level,
        }
    )


if __name__ == "__main__":
    """with app.test_client() as client:
    response = client.post(
        "/phishing",
        json={
            "html_content": "<html><body><a href='http://аpple.com'>Fake Link</a><input type='password'></body></html>"
        },
    )
    print(response.get_json())"""
    app.run(host="0.0.0.0", port=5000, debug=True)
