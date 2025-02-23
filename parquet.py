import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

df = pd.read_parquet("baris.parquet", engine="pyarrow")
df["IpLoc"] = df["IpLoc"].astype("string")

print(df.head())
print(df.info())


ipLocDict = {county: freq for county, freq in df["IpLoc"].value_counts().items()}
output = "\n".join(f"{str(k).upper()} : {v}" for k, v in ipLocDict.items())
print(output)


policyPublishedDict = {
    policy: freq for policy, freq in df["PolicyPublishedP"].value_counts().items()
}
output = "\n".join(
    f"{str(k).upper()} : %{round((v / len(df['PolicyPublishedP'])) * 100, 2)}"
    for k, v in policyPublishedDict.items()
)

print(output)
total_count = len(df["PolicyPublishedP"])
sorted_policies = dict(sorted(policyPublishedDict.items(), reverse=False))

plt.figure(figsize=(12, 10))
sns.barplot(
    x=list(sorted_policies.keys()),
    y=[(freq / total_count) * 100 for freq in sorted_policies.values()],
    palette="viridis",
)

plt.title("Policy Published Frequency Distribution", fontsize=14)
plt.xlabel("Policy Published P", fontsize=12)
plt.ylabel("Percentation", fontsize=12)
plt.xticks(rotation=45)
plt.show()


ipDict = {IPOwner: freq for IPOwner, freq in df["IPOwner"].value_counts().items()}
output = "\n".join(f"{str(k).upper()} : {v}" for k, v in ipDict.items())
print(output)

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
plt.show()

target_col = "IsSpam"
selected_cols = [
    "DMARCValidation",
    "SPFAuthentication",
    "SPFAlignment",
    "DKIMAuthentication",
    "DKIMAlignment",
]

correlations = df[[target_col] + selected_cols].corr()[target_col].drop(target_col)
print(f"'{target_col}' kolonunun seçili kolonlarla korelasyonu:")
print(correlations)

plt.figure(figsize=(12, 10))
sns.heatmap(correlations.to_frame(), annot=True, cmap="coolwarm", fmt=".2f")
plt.title(f"'{target_col}' Selected collums  correalation other collums ")
plt.show()

selected_columns = [
    "Volume",
    "PolicyDispositionValue",
    "HeuristicResultType",
    "DMARCValidation",
    "SPFAuthentication",
    "SPFAlignment",
    "DKIMAuthentication",
    "DKIMAlignment",
    "IsEnabled",
    "IsDeleted",
]
X = df[selected_columns]
Y = df["IsSpam"]


X_train, X_test, y_train, y_test = train_test_split(
    X, Y, test_size=0.2, random_state=42, stratify=Y
)

model = RandomForestClassifier(
    n_estimators=50,
    max_depth=7,
    min_samples_split=10,
    random_state=42,
)

model.fit(X_train, y_train)
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print(f"Model Doğruluk Oranı: {accuracy:.4f}")
print("\nSınıflandırma Raporu:")
print(classification_report(y_test, y_pred))
