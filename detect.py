import pandas as pd
from datetime import datetime

# Read the CSV file
df = pd.read_csv("login_logs.csv")

# Add new columns
df["alert"] = False
df["reason"] = ""
df["severity"] = ""

# Detection rules
suspicious_ips = ["185.220.101.5", "45.33.32.156"]
suspicious_countries = ["Russia", "China"]

for i, row in df.iterrows():
    reasons = []
    severity = ""

    # Rule 1: Suspicious country
    if row["country"] in suspicious_countries:
        reasons.append("Suspicious country")
        severity = "High"

    # Rule 2: Suspicious IP
    if row["source_ip"] in suspicious_ips:
        reasons.append("Suspicious IP")
        severity = "High"

    # Rule 3: Failed login
    if row["success"] == False:
        reasons.append("Failed login")
        if severity == "":
            severity = "Medium"

    # Rule 4: No MFA
    if row["mfa_used"] == False:
        reasons.append("No MFA")
        if severity == "":
            severity = "Low"

    if reasons:
        df.at[i, "alert"] = True
        df.at[i, "reason"] = " | ".join(reasons)
        df.at[i, "severity"] = severity

# Rule 5: Impossible Travel
df["timestamp"] = pd.to_datetime(df["timestamp"])
df = df.sort_values(["user", "timestamp"])

for user in df["user"].unique():
    user_logs = df[df["user"] == user].reset_index()
    for j in range(1, len(user_logs)):
        prev = user_logs.iloc[j-1]
        curr = user_logs.iloc[j]
        time_diff = (curr["timestamp"] - prev["timestamp"]).total_seconds() / 60
        if prev["country"] != curr["country"] and time_diff < 60:
            idx = user_logs.iloc[j]["index"]
            df.at[idx, "alert"] = True
            df.at[idx, "reason"] = df.at[idx, "reason"] + " | Impossible Travel"
            df.at[idx, "severity"] = "High"

# Rule 6: Brute Force
for user in df["user"].unique():
    user_logs = df[df["user"] == user]
    failed = user_logs[user_logs["success"] == False]
    if len(failed) >= 3:
        for idx in failed.index:
            df.at[idx, "alert"] = True
            if "Brute Force" not in str(df.at[idx, "reason"]):
                df.at[idx, "reason"] = df.at[idx, "reason"] + " | Brute Force Attempt"
            df.at[idx, "severity"] = "High"

# Save alerts
alerts = df[df["alert"] == True]
alerts.to_csv("alerts.csv", index=False)
print(f"Done! {len(alerts)} alerts found!")