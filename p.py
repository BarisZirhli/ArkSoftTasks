import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

df = pd.read_parquet("baris.parquet", engine="pyarrow")
df["IpLoc"] = df["IpLoc"].astype("string")

print(df.head())
# print(df.info())


ipLocDict = {county: freq for county, freq in df["IpLoc"].value_counts().items()}
output = "\n".join(f"{str(k).upper()} : {v}" for k, v in ipLocDict.items())
# print(output)


policyPublishedDict = {
    policy: freq for policy, freq in df["PolicyPublishedP"].value_counts().items()
}
output = "\n".join(
    f"{str(k).upper()} : %{round((v / len(df['PolicyPublishedP'])) * 100, 2)}"
    for k, v in policyPublishedDict.items()
)

# print(output)

ipDict = {IPOwner: freq for IPOwner, freq in df["IPOwner"].value_counts().items()}
output = "\n".join(f"{str(k).upper()} : {v}" for k, v in ipDict.items())
# print(output)

df_ip_volume = (
    df.groupby(["IpLoc"], as_index=False)["Volume"]
    .sum()
    .sort_values(by="Volume", ascending=False)
)
# print(f"Total volume of traffic {df["Volume"].sum()}")

print(df_ip_volume)
df_ip_volume = df_ip_volume[df_ip_volume["Volume"] > 2000]

# Toplam trafik hacmini yazdır
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

plt.title("IP Adresleri ve Toplam Volume Isı Haritası 2000 den büyük verileri içerir")
plt.xlabel("Toplam Volume", labelpad=10)
plt.xticks(rotation=45, fontsize=20)
plt.yticks(rotation=45, fontsize=20)

plt.show()
