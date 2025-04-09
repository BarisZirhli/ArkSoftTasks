import datetime
import whois
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import Levenshtein
import logging
import idna
import requests
import pytesseract
from PIL import Image
from io import BytesIO

logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s"
)


class TurkishDomains:

    global phishing_score
    risk_details = {
        "suspicious_links": [],
        "suspicious_forms": [],
        "suspicious_images": [],
        "threat_keywords": [],
        "suspicious_script": [],
        "total_score": 0.0,
    }

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
                r"garantibankası",
                r"yapikredi",
                r"halkbankweb",
                r"finansbank",
                r"teb",
                r"ziraat",
                r"trendyol",
                r"hepsiburada",
                r"n11",
                r"yemeksepeti",
                r"apple",
                r"amazon",
                r"wellsfargo",
                r"bofa",
                r"jpmorgan",
                r"tesla",
            ],
        }
    }


def load_turkish_model():
    return TurkishDomains.models_config["turkish"]


def is_cdn_photo(url: str):
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.head(url, allow_redirects=True, headers=headers, timeout=5)
        content_type = response.headers.get("Content-Type", "")
        return content_type.startswith("image/")
    except Exception as e:
        print(f"Error checking URL: {e}")
        return False


def is_image_content(url):
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        content_type = response.headers.get("Content-Type", "")
        return content_type.startswith("image/")
    except Exception as e:
        print(f"Error: {e}")
        return False


def is_image_url(url: str):
    image_extensions = (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tiff")
    return url.lower().endswith(image_extensions)


def download_image_to_memory(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Eğer HTTP hata kodu dönerse hata verir

        # Image'i belleğe al
        img_data = BytesIO(response.content)
        return img_data
    except requests.exceptions.RequestException as e:
        print(f"Resim indirme hatası: {e}")
        return None


def perform_ocr_from_memory(image_data):

    try:
        img = Image.open(image_data)
        text = pytesseract.image_to_string(img, lang="tur")
        return text
    except Exception as e:
        print(f"Resim işleme hatası: {e}")
        return None


def helper(url: str):

    image_data = download_image_to_memory(url)
    if image_data:
        result_text = perform_ocr_from_memory(image_data)
        if result_text:
            result_texts = str(result_text).split(" ")
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            punycode_domain = idna.encode(domain).decode()

            for text_part in result_texts:
                matching_keywords = [
                    keyword
                    for keyword in TurkishDomains.models_config["turkish"][
                        "threat_keywords"
                    ]
                    if keyword in text_part
                ]
                if matching_keywords:
                    TurkishDomains.phishing_score += 0.5
                    TurkishDomains.risk_details["threat_keywords"].append(
                        {
                            "url": punycode_domain,
                            "threat word": text_part,
                            "reason": "şüpheli kelime",
                        }
                    )


def analyze_turkish_html_phishing(html_content):
    model_config = load_turkish_model()

    soup = BeautifulSoup(html_content, "html.parser")
    TurkishDomains.phishing_score = 0.0
    phishing_score = 0.0

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

    for link in links:
        try:
            url = link["href"]
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            punycode_domain = idna.encode(domain).decode()
            # ASCII value regex shortcut
            new_url = re.sub(r"[^\x00-\x7F]+", "", url)

            if new_url != url or str(punycode_domain).startswith("xn--"):
                phishing_score += 3
                TurkishDomains.risk_details["suspicious_links"].append(
                    {"url": punycode_domain, "reason": "PunyCode Sahteciliği"}
                )
                scores = [
                    Levenshtein.ratio(domain, company)
                    for company in model_config["sensitive_domains"]
                ]

                if max(scores) >= 0.60 and max(scores) < 100:
                    phishing_score += 3
                    TurkishDomains.risk_details["suspicious_links"].append(
                        {"url": punycode_domain, "reason": "Domain Sahteciliği"}
                    )
        except Exception as e:
            logging.error(f"Link has a problem")

        try:
            domain_info = whois.whois(domain)
            creation_datetime = domain_info.creation_date
            if isinstance(creation_datetime, list):
                creation_datetime = creation_datetime[0]

            years_difference = (datetime.datetime.now() - creation_datetime).days / 365
            if years_difference < 5:
                phishing_score += 2
                TurkishDomains.risk_details["suspicious_links"].append(
                    {
                        "url": punycode_domain,
                        "reason": "Domain yaşından Domain Sahteciliği",
                    }
                )
        except Exception as e:
            logging.error(f"Error fetching WHOIS data:")

        # Handle short URLs
        if any(shortener in url for shortener in shorteners):
            phishing_score += 2
            TurkishDomains.risk_details["suspicious_links"].append(
                {"url": url, "reason": "Kısaltılmış URL"}
            )
            if is_image_url(url):
                helper(url)

            if is_cdn_photo(url):
                helper(url)

            if is_image_content(url):
                helper(url)

    forms = soup.find_all("form")

    if forms:
        for form in forms:
            action = form.get("action")
            if action and "http" in action:
                phishing_score += 1

                TurkishDomains.risk_details["suspicious_forms"].append(
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

                    TurkishDomains.risk_details["suspicious_forms"].append(
                        {"input": input_name, "reason": "Hassas girdi alanı"}
                    )

    images = soup.find_all("img")

    if images:
        for img in images:
            src = img.get("src")
            if src and (re.match(r"^data:image/.+;base64,", src)):
                phishing_score += 1
                TurkishDomains.risk_details["suspicious_images"].append(
                    {"src": src, "reason": "Base64 kodlu görsel"}
                )
            # QR maybe
            alt_text = img.get("alt", "").lower()
            if "scan" in alt_text or any(
                keyword in alt_text for keyword in model_config["threat_keywords"]
            ):
                phishing_score += 0.5
                TurkishDomains.risk_details["suspicious_images"].append(
                    {"alt": alt_text, "reason": "Şüpheli görsel açıklaması"}
                )

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
                phishing_score += 0.5
                TurkishDomains.risk_details["threat_keywords"].append(
                    {
                        "url": punycode_domain,
                        "threat word": word,
                        "reason": "şüpheli kelime",
                    }
                )

        suspicious_text_patterns = [
            r"\b\d{10,}\b",
            r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}",
            r"\+\d{10,}",
            r"\b(IBAN|TR\d{2})\d{16}\b",
        ]
        for pattern in suspicious_text_patterns:
            if re.search(pattern, plain_text, re.IGNORECASE):
                phishing_score += 0.5

    table = soup.find("table")

    if table:
        inputs = table.find_all("input")
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
        for input in inputs:
            input_type = input.get("type", "").lower()
            input_name = input.get("name", "").lower()
            if any(
                sens_type in input_type or sens_type in input_name
                for sens_type in sensitive_input_types
            ):
                phishing_score += 1.5

                TurkishDomains.risk_details["suspicious_forms"].append(
                    {"input": input_name, "reason": "Hassas girdi alanı"}
                )

    iframes = soup.find_all("iframe")

    if iframes:
        for iframe in iframes:
            iframe_src = iframe.get("src")
            if iframe_src:
                if "http" in iframe_src and not any(
                    domain in iframe_src for domain in model_config["sensitive_domains"]
                ):
                    phishing_score += 1
                    TurkishDomains.risk_details["suspicious_iframes"].append(
                        {"src": iframe_src, "reason": "Şüpheli iframe kaynağı"}
                    )

    scripts = soup.find_all("script")

    if scripts:
        for script in scripts:
            script_content = script.get_text()
            if "fetch" in script_content and "http" in script_content:
                if not any(
                    domain in script_content
                    for domain in model_config["sensitive_domains"]
                ):
                    phishing_score += 1.5
                    TurkishDomains.risk_details["suspicious_fetch_requests"].append(
                        {
                            "script": script_content,
                            "reason": "Fetch kullanılarak şüpheli veri gönderimi",
                        }
                    )
            if "atob" in script_content:
                phishing_score += 3
                TurkishDomains.risk_details["suspicious_script"].append(
                    {
                        "scprit": script_content,
                        "reason": "Atob kullanarak gömülü bir şey çalıştırılmaya çalışılıyor",
                    }
                )

    # Return phishing score and risk details
    TurkishDomains.risk_details["total_score"] = phishing_score
    return TurkishDomains.risk_details


def classify_phishing_risk(risk_details):
    score = risk_details["total_score"]

    if score <= 1:
        return "Çok Düşük Risk"
    elif 1 < score <= 2.5:
        return "Orta Risk"
    elif 2.5 < score <= 3.5:
        return "Yüksek Risk"
    else:
        return "Çok Yüksek Risk"


def main():

    turkish_sample1 = """
     <html>
    <body>
        <a href="http://garantibank.com">Hesap güvenliğini doğrula</a>
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
        
        <img src="http://garantibank.com/logo.png" alt="Garantibank">
    </body>
    </html>
    """

    turkish_sample2 = """
     <html>
    <body>
        <a href="http://аpple.com">Hesap güncellemeleri için tıklayınız</a>
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
