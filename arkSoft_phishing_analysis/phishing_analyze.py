import torch
import numpy as np
import requests
import json
import dotenv
import os
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from email.parser import BytesParser
from email import policy
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re
import nltk
from nltk.stem import PorterStemmer

dotenv.load_dotenv()


nltk.download("punkt")
stemmer = PorterStemmer()



#English model for sentiment analysis 
english_model_name = "distilbert-base-uncased"
tokenizer = AutoTokenizer.from_pretrained(english_model_name)
model = AutoModelForSequenceClassification.from_pretrained(english_model_name)

# URL safety checker with Google safety with API
def check_url_with_google_safe_browsing(api_key, url_to_check):
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "yourcompanyname", "clientVersion": "1.5.2"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url_to_check}],
        },
    }
    headers = {"Content-Type": "application/json"}
    response = requests.post(api_url, headers=headers, data=json.dumps(payload))

    if response.status_code == 200:
        result = response.json()
        if "matches" in result:
            return 1
        else:
            return 0
    else:
        return -1

#Phishing Score Calculator
def calculate_phishing_score(msg, api_key):
    phishing_score = 0.0
    attachments = list()
#Program handles .eml extentioned file in order to review whole mail content.
    html_content = None
    if msg.is_multipart():
        for part in msg.iter_parts():
            if part.get_content_type() == "text/html":
                html_content = part.get_payload(decode=True).decode(
                    part.get_content_charset()
                )
            elif part.get_content_disposition() == "attachment":
                filename = part.get_filename()
                if filename:
                    file_content = part.get_payload(decode=True)
                    attachments.append((filename, file_content))
    else:
        if msg.get_content_type() == "text/html":
            html_content = msg.get_payload(decode=True).decode(
                msg.get_content_charset()
            )
            for part in msg.iter_attachments():
                filename = part.get_filename()
                if filename:
                    file_content = part.get_payload(decode=True)
                    attachments.append((filename, file_content))


    if html_content:
        soup = BeautifulSoup(html_content, "html.parser")
#Masked url caused potential risky case attacker might be hidden under the shorten links. These are most popular link shortener services.
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
        ]
        links = soup.find_all("a", href=True)
        if links:
            for link in links:
                url = link["href"]
                if any(shortener in url for shortener in shorteners):
                    phishing_score += 1.5

                parsed_url = urlparse(url)
                result = check_url_with_google_safe_browsing(parsed_url, api_key)
                if result == 1:
                    phishing_score += 2
                elif result == -1:
                    phishing_score += 1
                else:
                    phishing_score += 0.5

        forms = soup.find_all("form")
        if forms:
            for form in forms:
                action = form.get("action")
                if action and "http" in action:
                    phishing_score += 1
                inputs = form.find_all("input")
                for input_tag in inputs:
                    input_type = input_tag.get("type", "").lower()
                    if input_type in ["password", "email", "text", "number", "file"]:
                        phishing_score += 1

        images = soup.find_all("img")
        if images:
            for img in images:
                src = img.get("src")
                if src and re.match(r'^data:image/.+;base64,', src):
                    phishing_score += 1

        body = soup.find("body")
        if body:
            plain_text = body.get_text(separator=" ").strip()
            plain_text = re.sub(r"\s+", " ", plain_text).strip()
            threat_keywords = [
                "verify",
                "urgent",
                "visit",
                "account",
                "security",
                "login",
                "password",
                "update",
                "confirm",
                "immediately",
                "suspicious",
                "alert",
                "safety",
                "sensitive",
                "protected",
                "risk",
            ]
#Used NLTK and stemmer to catch pontential threat words
            words = nltk.word_tokenize(plain_text)
            stemmed_words = [stemmer.stem(word.lower()) for word in words]

            for word in stemmed_words:
                if any(threat_word in word for threat_word in threat_keywords):
                    phishing_score += 1
#Sentinal analyis used to catch aggressive suspection statements such as "I love you, call me pls +0121212121212" Or "You acc. has been hacked Hurry up,rush."
            inputs = tokenizer(
                plain_text, return_tensors="pt", truncation=True, padding=True
            )
            with torch.no_grad():
                logits = model(**inputs).logits
            probabilities = torch.softmax(logits, dim=1).numpy()[0]
            max_index = np.argmax(probabilities)

            confidence = round(probabilities[max_index], 2)
            if confidence < 0.5:
                phishing_score += 0.2
            elif confidence < 0.6:
                phishing_score += 0.45
            elif confidence < 0.7:
                phishing_score += 0.85
            elif confidence < 0.85:
                phishing_score += 1.5
            else:
                phishing_score += 2

        if any(
            str(attachment[0]).endswith(ex)
            for ex in [".exe", ".vbs", ".scr", ".bat"]
            for attachment in attachments
        ):
            phishing_score += 2.5
            
        if any(
            str(attachment[0]).endswith(ex)
            for ex in [".pdf", ".csv", ".xlsx", ".txt"]
            for attachment in attachments
        ):
            phishing_score += 1.25    

    return phishing_score


PHISHING_THRESHOLD = 0.7
api_key = os.getenv("API_KEY")

with open("email/sample-4631.eml", "rb") as file:
    msg = BytesParser(policy=policy.default).parse(file)

phishing_score = calculate_phishing_score(msg, api_key)

print(f"Phishing Score: {phishing_score}")


#Potential test cases will write soon