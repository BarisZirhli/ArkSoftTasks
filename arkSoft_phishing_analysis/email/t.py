from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
from bs4 import BeautifulSoup
import numpy as np

# Farklı bir model (dbmdz/bert-base-turkish-128k-uncased)
model_name = "dbmdz/bert-base-turkish-128k-uncased"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForSequenceClassification.from_pretrained(model_name)

# HTML içeriği
email_body = """
<html>
<body>
    <h1>Hesabınızda Güvenlik Sorunu! Hemen Giriş Yapın!</h1>
    <p>Merhaba <strong>[Kullanıcı Adı]</strong>,</p>
    <p>Hesabınızda olağandışı bir aktivite tespit edildi. Güvenliğiniz için hesabınıza erişimi hemen sınırladık. Lütfen aşağıdaki bağlantıya tıklayarak güvenli giriş yapın ve hesabınızı tekrar etkinleştirin.</p>
    <p><a href="https://fake-bank-login.com" target="_blank" style="color: red; font-weight: bold;">Hesabınızı Tekrar Etkinleştirin</a></p>
    <p>Eğer bu işlemi yapmazsanız, hesabınız 24 saat içinde tamamen kilitlenecektir. Bu nedenle işlemi hemen tamamlamanızı öneririz.</p>
    <p>Saygılarımızla,</p>
    <p><strong>[Fake Bank Adı] Destek Ekibi</strong></p>
</body>
</html>
"""

# HTML'den metni çıkarma (BeautifulSoup kullanarak)
soup = BeautifulSoup(email_body, "html.parser")
plain_text = soup.get_text(separator=" ")  # HTML etiketlerini temizler
print("📝 Temiz Metin:\n", plain_text)


# Tokenize et ve modelin giriş formatına getir
inputs = tokenizer(plain_text, return_tensors="pt", truncation=True, padding=True)

# Modeli çalıştır ve logits hesapla
with torch.no_grad():
    logits = model(**inputs).logits

# Softmax ile olasılıkları hesapla
probabilities = torch.softmax(logits, dim=1).numpy()[0]
print(probabilities)
# En yüksek olasılıkla etiket seç
max_index = np.argmax(probabilities)

confidence = round(probabilities[max_index], 2)

# Sonuçları yazdır
print(f"\n📌 Temizlenmiş Metin: {plain_text}")
print(f"(Güven: {confidence})")
