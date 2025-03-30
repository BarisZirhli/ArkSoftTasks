import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import Levenshtein
import logging

# Set up logging
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s"
)


class TurkishStemmer:

    models_config = {
        "turkish": {
            "threat_keywords": [
                "doğrula",
                "acil",
                "ziyaret",
                "hesap",
                "güvenlik",
                "giriş",
                "şifre",
                "güncelle",
                "onayla",
                "hemen",
                "şüpheli",
                "uyarı",
                "emniyet",
                "hassas",
                "korunmuş",
                "risk",
                "tehlike",
                "acilen",
                "derhal",
                "tehdit",
                "kredi",
                "banka",
                "ödeme",
                "işlem",
            ],
            "sensitive_domains": [
                r"ibankmobil",
                r"akbanknet",
                r"internetsubesi",
                r"garanti\w*",
                r"yapikredi",
                r"halkbankweb",
                r"finansbank",
                r"teb\.com",
                r"ziraat\w*",
                r"trendyol",
                r"hepsiburada",
                r"n11",
                r"yemeksepeti",
                r"apple",
            ],
        }
    }


def load_turkish_model():
    model_config = TurkishStemmer.models_config["turkish"]
    return model_config


def analyze_turkish_html_phishing(html_content):
    model_config = load_turkish_model()

    phishing_score = 0.0
    risk_details = {
        "suspicious_links": [],
        "suspicious_forms": [],
        "suspicious_images": [],
        "threat_keywords": [],
        "total_score": 0.0,
    }

    # Parse HTML content
    soup = BeautifulSoup(html_content, "html.parser")
    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "goo.gl",
        "ow.ly",
        "buff.ly",
        "short.io",
        "bl.ink",
        "is.gd",
        "Replug.io",
        "Cutt.us",
        "Rebrandly.com",
        "Wow.link",
        "Innkin.com",
        "Goo.su",
        "T2M",
        "kisa.link",
        "k.url",
        "ozurl.net",
        "k.link",
    ]

    links = soup.find_all("a", href=True)

    if links:
        for link in links:
            url = link["href"]
            # only ASCII characters allow
            new_url = re.sub(r"[^\x00-\x7F]+", "", url)
            if new_url != url:
                phishing_score += 2
            url_domain_pattern = r"^(?:https?://)?(?:www\.)?([^/]+)\.com"
            match = re.match(url_domain_pattern, url)
            sensitive_companies = model_config["sensitive_domains"]
            if match:
                regex_url = match.group(1)
                scores = [
                    Levenshtein.ratio(regex_url, company)
                    for company in sensitive_companies
                ]
                max_score = max(scores)

                if max_score >= 0.60 and max_score < 100:
                    phishing_score += 3

            if any(shortener in url for shortener in shorteners):
                phishing_score += 1.5
                risk_details["suspicious_links"].append(
                    {"url": url, "reason": "Kısaltılmış URL"}
                )

            parsed_url = urlparse(url)
            suspicious_patterns = model_config["sensitive_domains"]

            if any(
                re.search(pattern, parsed_url.netloc, re.IGNORECASE)
                for pattern in suspicious_patterns
            ):
                phishing_score += 1

                risk_details["suspicious_links"].append(
                    {"url": url, "reason": "Şüpheli alan adı"}
                )

    # Check forms
    forms = soup.find_all("form")

    if forms:
        for form in forms:
            action = form.get("action")
            if action and "http" in action:
                phishing_score += 1

                risk_details["suspicious_forms"].append(
                    {"action": action, "reason": "Dış kaynaklı form eylemi"}
                )

            inputs = form.find_all("input")
            sensitive_input_types = [
                "şifre",
                "parola",
                "eposta",
                "hesap",
                "kredi",
                "kart",
                "güvenlik",
                "email",
            ]
            for input_tag in inputs:
                input_type = input_tag.get("type", "").lower()
                input_name = input_tag.get("name", "").lower()

                if any(
                    sens_type in input_type or sens_type in input_name
                    for sens_type in sensitive_input_types
                ):
                    phishing_score += 1.5

                    risk_details["suspicious_forms"].append(
                        {"input": input_name, "reason": "Hassas girdi alanı"}
                    )

    # Check images
    images = soup.find_all("img")

    if images:
        for img in images:
            src = img.get("src")
            if src and re.match(r"^data:image/.+;base64,", src):
                phishing_score += 1

                risk_details["suspicious_images"].append(
                    {"src": src, "reason": "Base64 kodlu görsel"}
                )

            alt_text = img.get("alt", "").lower()
            if len(alt_text) > 100 or any(
                keyword in alt_text for keyword in model_config["threat_keywords"]
            ):
                phishing_score += 0.5

                risk_details["suspicious_images"].append(
                    {"alt": alt_text, "reason": "Şüpheli görsel açıklaması"}
                )

    # Analyze body text
    body = soup.find("body")
    if body:
        plain_text = body.get_text(separator=" ").strip()
        plain_text = re.sub(r"\s+", " ", plain_text).strip()
        words = plain_text.split()

        for word in words:
            matching_keywords = [
                keyword
                for keyword in model_config["threat_keywords"]
                if keyword in word
            ]
            if matching_keywords:
                phishing_score += 1

                risk_details["threat_keywords"].extend(matching_keywords)

        suspicious_text_patterns = [
            r"\b\d{10,}\b",
            r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}",
            r"\+\d{10,}",
            r"\b(IBAN|TR\d{2})\d{16}\b",
        ]
        for pattern in suspicious_text_patterns:
            if re.search(pattern, plain_text, re.IGNORECASE):
                phishing_score += 0.5

    # Return phishing score and risk details

    risk_details["total_score"] = phishing_score

    return risk_details


def classify_phishing_risk(risk_details):
    score = risk_details["total_score"]

    if score <= 1:
        return "Düşük Risk"
    elif 1 < score <= 2:
        return "Orta Risk"
    elif 2 < score <= 3:
        return "Yüksek Risk"
    else:
        return "Çok Yüksek Risk"


def main():
    turkish_sample1 = """
     <html>
    <body>
        <a href="http://garatibank.com">Hesap güvenliğini doğrula</a>
        <table>
    <tr>
        <td>
            <input type="password" name="parola">
        </td>
        
        <td>
            <input type="text" name="email">
        </td>
    </tr>
    </table>
        
        <img src="http://garatibank.com/logo.png" alt="Garantibank">
    </body>
    </html>
    """

    turkish_sample2 = """
     <html>
    <body>
        <a href="http:// аpple.com">Hesap güncellemeleri için tıklayınız</a>
        <table>
    <tr>
        <td>
            <input type="password" name="sifreniz">
        </td>
        
        <td>
            <input type="text" name="telefon">
        </td>
    </tr>
    </table>
        
        <img src="http://hepsiburda.com/logo.png" alt="Hepsiburada">
    </body>
    </html>
    """

    logging.info("Sample 1:")
    risk_details1 = analyze_turkish_html_phishing(turkish_sample1)
    risk_level1 = classify_phishing_risk(risk_details1)

    logging.info(f"Toplam Risk Skoru: {risk_details1['total_score']}")
    logging.info(f"Risk Seviyesi: {risk_level1}")

    for category, risks in risk_details1.items():
        if isinstance(risks, list) and risks:
            logging.info(f"\n{category.capitalize()}:")
            for risk in risks:
                logging.info(f"  - {risk}")

    logging.info("\n" + "-" * 40)
    logging.info("\nSample 2:")
    risk_details2 = analyze_turkish_html_phishing(turkish_sample2)
    risk_level2 = classify_phishing_risk(risk_details2)

    logging.info("Phishing Risk Detayları:")
    logging.info(f"Toplam Risk Skoru: {risk_details2['total_score']}")
    logging.info(f"Risk Seviyesi: {risk_level2}")

    for category, risks in risk_details2.items():
        if isinstance(risks, list) and risks:
            logging.info(f"\n{category.capitalize()}:")
            for risk in risks:
                logging.info(f"  - {risk}")


if __name__ == "__main__":
    main()
