from sklearn.feature_extraction.text import TfidfVectorizer

texts = [
    "Click here to reset your password",  # phishing
    "Meeting rescheduled for tomorrow",  # not phishing
    "Urgent: Your account needs verification",  # phishing
    "Let's catch up over coffee",  # not phishing
]

vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(texts)
print(X)
print(vectorizer.get_feature_names_out())
print(X.toarray())
