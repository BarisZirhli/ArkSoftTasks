import os
import joblib
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import cross_val_score
from sklearn.metrics import confusion_matrix
from sklearn.metrics import accuracy_score, classification_report

# Read file

df = pd.read_parquet("DMARC.parquet", engine="pyarrow")
df["IpLoc"] = df["IpLoc"].astype("string")

# print(df.head())
# print(df.info())
"""
print(df.isna().any().any())
print(df.isna().sum())
print(len(df["IsSpam"]))
print(df.shape)

"""

# IP based location declaration
ipLocDict = {county: freq for county, freq in df["IpLoc"].value_counts().items()}
output = "\n".join(f"{str(k).upper()} : {v}" for k, v in ipLocDict.items())
# print(output)

# Percentage of Mail Policy Compliance
policyPublishedDict = {
    policy: freq for policy, freq in df["PolicyPublishedP"].value_counts().items()
}
output = "\n".join(
    f"{str(k).upper()} : %{round((v / len(df['PolicyPublishedP'])) * 100, 2)}"
    for k, v in policyPublishedDict.items()
)

# print(output)
total_count = len(df["PolicyPublishedP"])
sorted_policies = dict(sorted(policyPublishedDict.items(), reverse=False))

plt.figure(figsize=(12, 14))
sns.barplot(
    x=list(sorted_policies.keys()),
    y=[(freq / total_count) * 100 for freq in sorted_policies.values()],
    palette="viridis",
)

plt.title("Policy Published Frequency Distribution", fontsize=14)
plt.xlabel("Policy Published P", fontsize=12)
plt.ylabel("Percentation", fontsize=12)
plt.xticks(rotation=45)
# plt.show()

# IP Owner number
ipDict = {IPOwner: freq for IPOwner, freq in df["IPOwner"].value_counts().items()}
output = "\n".join(f"{str(k).upper()} : {v}" for k, v in ipDict.items())
# print(output)

ip_owner_counts = df["IPOwner"].value_counts()
high_freq_owners = ip_owner_counts[ip_owner_counts > 50000].index
df_IPOwner = df[df["IPOwner"].isin(high_freq_owners)]
ip_counts_filtered = df_IPOwner["IPOwner"].value_counts()

plt.figure(figsize=(12, 10))
sns.barplot(x=ip_counts_filtered.index, y=ip_counts_filtered.values, palette="viridis")

plt.xticks(rotation=45)
plt.xlabel("IP Owner")
plt.ylabel("Count")
plt.title("More than 50000 Repeat IPOwner Values")
# plt.show()


# Volume intensity per Location
df_ip_volume = (
    df.groupby(["IpLoc"], as_index=False)["Volume"]
    .sum()
    .sort_values(by="Volume", ascending=False)
)

print(f"Total volume of traffic {df["Volume"].sum()}")
print(df_ip_volume)

df_ip_volume = df_ip_volume[df_ip_volume["Volume"] > 2000]


print(f"Total volume of traffic: {df['Volume'].sum()}")
print(f"Enable connection out of % {df['IsEnabled'].mean() * 100:.2f}")

df_heatmap = df_ip_volume.set_index("IpLoc")[["Volume"]].astype(float).T

plt.figure(figsize=(20, 20))
sns.heatmap(
    df_heatmap,
    cmap="coolwarm",
    annot=True,
    fmt=".0f",
    linewidths=1,
    annot_kws={"size": 8},
)

plt.title("IP Adresses and Total Volume heatmap contains bigger than 2000")
plt.xlabel("Total Volume", labelpad=10)
plt.xticks(rotation=45, fontsize=20)
plt.yticks(rotation=45, fontsize=20)
# plt.show()

target_col = "IsSpam"
selected_cols = [
    "DMARCValidation",
    "SPFAuthentication",
    "SPFAlignment",
    "DKIMAuthentication",
    "DKIMAlignment",
]

# Spam correlation with target collum
correlations = df[[target_col] + selected_cols].corr()[target_col].drop(target_col)
print(f"'{target_col}' kolonunun seçili kolonlarla korelasyonu:")
print(correlations)

plt.figure(figsize=(12, 10))
sns.heatmap(
    correlations.sort_values(ascending=False).to_frame(),
    annot=True,
    cmap="coolwarm",
    fmt=".2f",
)
plt.title(f"'{target_col}' Selected collums  correalation other collums ")
# plt.show()

# ML application using LogisticRegretion


# For Spoofing detection likely useful collums
selected_columns = [
    "SPFAuthentication",
    "DKIMAuthentication",
    "DMARCValidation",
    "DKIMAlignment",
    "Volume",
    "IsSpam",
]

# Label encoding Operation if any
label_encoder = LabelEncoder()
for col in selected_columns:
    df[col] = label_encoder.fit_transform(df[col])

y = df[
    "IsDeleted"
]  # IsSpam column not proper because this created by selected some collumns
X = df[selected_columns]

# Split train and test data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Create model and train
logreg = LogisticRegression(class_weight="balanced", max_iter=10000, C=0.1)
logreg.fit(X_train, y_train)

# Predict witk test data
y_pred = logreg.predict(X_test)

# Calculate model accurancy currently approximately 0.975
accuracy = accuracy_score(y_test, y_pred)
print(f"Model Accuracy: {accuracy:.4f}")
print("Classification Report:")
print(classification_report(y_test, y_pred))


# Extract which is obtained model
if not os.path.exists("ARKSOFT_DMARC_ANALYSIS.pkl"):
    joblib.dump(logreg, "ARKSOFT_DMARC_ANALYSIS.pkl")

cm = confusion_matrix(y_test, y_pred)

for i in range(len(cm)):
    for j in range(len(cm[i])):
        print(f"cm[{i}][{j}] = {cm[i][j]}")

# Separates 5 different parts and applies independent model prediction
cv_scores = cross_val_score(logreg, X, y, cv=5)
print("Cross-validation scores:", cv_scores)
