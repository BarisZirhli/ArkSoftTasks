import pandas as pd
import chardet
import numpy as np
import requests
import dotenv
import os

dotenv.load_dotenv()
result = ""
with open("datas.csv", "rb") as f:
    result = chardet.detect(f.read(100000))

df = pd.read_csv(
    "datas.csv", low_memory=False, encoding=result["encoding"], on_bad_lines="skip"
)

df = df.shift(periods=1, axis=1)
df.iloc[:, 0] = range(1, len(df) + 1)
df = df.loc[:, ~df.columns.str.contains("Guid", case=True)]
df = df.apply(lambda x: x.where(x.notna(), None))
df["IsEnabled"] = df["IsDeleted"].apply(lambda x: 1 if x == 0 else 0)
df["IsDeleted"] = df["IsEnabled"].apply(lambda x: 1 if x == 0 else 0)

columns_to_drop = [
    "CreatedBy",
    "CreatedAt",
    "ModifiedBy",
    "OverrideReasonType",
    "OverrideReasonTypeComment",
    "PolicyPublishedAdkim",
    "PolicyPublishedAspf",
    "PolicyDisposition",
    "EnvelopeTo",
    "PolicyPublishedSp",
]
df = df.drop(columns=columns_to_drop, errors="ignore")
df = df.dropna(axis=1, how="all")

df["Id"] = pd.to_numeric(df["Id"], errors="coerce").astype("Int64")
df["PolicyDispositionValue"] = pd.to_numeric(
    df["PolicyDispositionValue"], errors="coerce"
).astype("Int64")
df["Volume"] = pd.to_numeric(df["Volume"], errors="coerce").astype("Int64")
df["SPFAuthentication"] = pd.to_numeric(
    df["SPFAuthentication"], errors="coerce"
).astype("Int64")
df["SPFAlignment"] = pd.to_numeric(df["SPFAlignment"], errors="coerce").astype("Int64")
df["DKIMAuthentication"] = pd.to_numeric(
    df["DKIMAuthentication"], errors="coerce"
).astype("Int64")
df["DKIMAlignment"] = pd.to_numeric(df["DKIMAlignment"], errors="coerce").astype(
    "Int64"
)
df["IsEnabled"] = pd.to_numeric(df["IsEnabled"], errors="coerce").astype("Int64")
df["IsDeleted"] = pd.to_numeric(df["IsDeleted"], errors="coerce").astype("Int64")

df["DateRangeBegin"] = pd.to_datetime(df["DateRangeBegin"], errors="coerce")
df["DateRangeEnd"] = pd.to_datetime(df["DateRangeEnd"], errors="coerce")

df["HeuristicResultType"] = pd.to_numeric(
    df["HeuristicResultType"], errors="coerce"
).astype("Int64")
df["DMARCValidation"] = pd.to_numeric(df["DMARCValidation"], errors="coerce").astype(
    "Int64"
)

string_columns = [
    "OrgName",
    "Email",
    "Domain",
    "DomainRoot",
    "PolicyPublishedP",
    "SourceIP",
    "IPOwner",
    "PTR",
    "HeaderFrom",
    "EnvelopeFrom",
    "HeuristicResultTypeText",
    "HeuristicComment",
]

for col in string_columns:
    if col in df.columns:
        df[col] = df[col].astype("string")

isNullCollumNumber = df.isnull().sum()
isNaCollumNumber = df.isna().sum()
print(isNaCollumNumber)
print(isNullCollumNumber)
df = df.dropna(axis=0, how="any")

print(df.dtypes)

SPAM_THRESHOLD = 0.6


def spamScore(row: pd) -> int:
    spamS = 0

    if row["DMARCValidation"] == 0:
        spamS += 0.2
    if row["SPFAuthentication"] == 0:
        spamS += 0.2
    if row["SPFAlignment"] == 0:
        spamS += 0.2
    if row["DKIMAuthentication"] == 0:
        spamS += 0.2
    if row["DKIMAlignment"] == 0:
        spamS += 0.2
    if row["HeuristicResultTypeText"] in ["HalfCompliant", "NonCompliant"]:
        spamS += 0.2

    return 1 if spamS > SPAM_THRESHOLD else 0


ip_cache = {}


def getCountryFromIP(ip_address: str) -> str:

    if ip_address in ip_cache:
        print(f"Cache hit: {ip_address} -> {ip_cache[ip_address]}")
        return ip_cache[ip_address]

    try:
        print(f"Fetching country for IP: {ip_address}")
        headers = {"Accept-Encoding": "identity"}
        response = requests.get(
            f"http://ipinfo.io/{ip_address}?{os.getenv("token")}",
            timeout=5,
        )

        if response.status_code == 200:
            data = response.json()
            country = data.get("country", "Unknown")

            ip_cache[ip_address] = country
            print(f"API Response: {ip_address} -> {country}")
            return country
        else:
            print(
                f"Failed to fetch data for {ip_address}, Status: {response.status_code}"
            )
            return "Unknown"

    except requests.exceptions.RequestException as e:
        print(f"Error fetching IP info for {ip_address}: {e}")
        return "Error"


df["IpLoc"] = df["SourceIP"].apply(lambda ip: getCountryFromIP(ip))
df["IsSpam"] = df.apply(spamScore, axis=1)

print(df["IsSpam"].value_counts())
print(df.head())

df.to_csv("DMARC.csv", index=False)
df.to_parquet("DMARC.parquet", engine="pyarrow", index=False)
