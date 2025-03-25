import re
import torch
import nltk
import numpy as np
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# Download NLTK resources
nltk.download("punkt")


# Custom Turkish Stemmer
class TurkishStemmer:
    def __init__(self):
        # Common Turkish suffixes to remove
        self.suffixes = [
            # Plural suffixes
            "ler",
            "lar",
            # Case suffixes
            "de",
            "da",
            "te",
            "ta",
            "den",
            "dan",
            "ten",
            "tan",
            "i",
            "ı",
            "u",
            "ü",
            "yi",
            "yı",
            "yu",
            "yü",
            "e",
            "a",
            "ye",
            "ya",
            # Possession suffixes
            "m",
            "ım",
            "im",
            "um",
            "ün",
            "un",
            "n",
            "nız",
            "niz",
            "nuz",
            "nüz",
            # Verb suffixes
            "mak",
            "mek",
            "yor",
            "di",
            "dı",
            "du",
            "dü",
            "tı",
            "ti",
            "tu",
            "tü",
        ]

    def stem(self, word: str):

        word = word.lower().strip(True)
        # Remove suffixes
        for suffix in self.suffixes:
            if word.endswith(suffix):
                word = word[: -len(suffix)]
                break

        return word


models_config = {
    "turkish": {
        "model_name": "dbmdz/bert-base-turkish-uncased",
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
        ],
        "stemmer": TurkishStemmer(),
    }
}


def load_turkish_model():

    model_config = models_config["turkish"]
    tokenizer = AutoTokenizer.from_pretrained(model_config["model_name"])
    model = AutoModelForSequenceClassification.from_pretrained(
        model_config["model_name"]
    )
    return tokenizer, model, model_config


def analyze_turkish_html_phishing(html_content):

    tokenizer, model, model_config = load_turkish_model()

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

            if any(shortener in url for shortener in shorteners):
                phishing_score += 1.5
                risk_details["suspicious_links"].append(
                    {"url": url, "reason": "Kısaltılmış URL"}
                )

            parsed_url = urlparse(url)
            suspicious_patterns = model_config["sensitive_domains"] + [
                r"login\d*\.",
                r"verify\d*\.",
                r"hesap\d*\.",
                r"secure\d*\.",
                r"auth\d*\.",
                r"\.ml$",
                r"\.ga$",
                r"\.cf$",
            ]

            if any(
                re.search(pattern, parsed_url.netloc, re.IGNORECASE)
                for pattern in suspicious_patterns
            ):
                phishing_score += 1
                risk_details["suspicious_links"].append(
                    {"url": url, "reason": "Şüpheli alan adı"}
                )

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

    # Analyze text content
    body = soup.find("body")
    if body:
        plain_text = body.get_text(separator=" ").strip()
        plain_text = re.sub(r"\s+", " ", plain_text).strip()

        # Tokenize and stem words
        words = nltk.word_tokenize(plain_text)
        stemmed_words = [model_config["stemmer"].stem(word.lower()) for word in words]

        # Check for threat keywords
        for word in stemmed_words:
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

        inputs = tokenizer(
            plain_text, return_tensors="pt", truncation=True, padding=True
        )
        with torch.no_grad():
            logits = model(**inputs).logits
        probabilities = torch.softmax(logits, dim=1).numpy()[0]
        max_index = np.argmax(probabilities)

        confidence = round(probabilities[max_index], 2)
        risk_mapping = {
            (0.0, 0.5): 0.2,
            (0.5, 0.6): 0.45,
            (0.6, 0.7): 0.85,
            (0.7, 0.85): 1.5,
            (0.85, 1.0): 2.0,
        }

        for (low, high), score_increment in risk_mapping.items():
            if low <= confidence < high:
                phishing_score += score_increment
                break

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


# Example usage
def main():
    turkish_sample = """
    <html>
    <body>
        <a href="http://kisa.link/suspicious-link">Acil: Hesabınızı Doğrulayın</a>
        <form action="http://fake-banka-giris.com">
            <input type="password" name="sifre">
            <input type="email" name="eposta">
        </form>
        <img src="data:image/png;base64,somefakebase64data" alt="Güvenlik Uyarısı">
    </body>
    </html>
    """

    risk_details = analyze_turkish_html_phishing(turkish_sample)
    risk_level = classify_phishing_risk(risk_details)

    print("Phishing Risk Detayları:")
    print(f"Toplam Risk Skoru: {risk_details['total_score']}")
    print(f"Risk Seviyesi: {risk_level}")

    # Detaylı risk bilgilerini yazdır
    for category, risks in risk_details.items():
        if isinstance(risks, list) and risks:
            print(f"\n{category.capitalize()}:")
            for risk in risks:
                print(f"  - {risk}")


if __name__ == "__main__":
    main()
