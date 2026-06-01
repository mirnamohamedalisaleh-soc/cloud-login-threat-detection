import pandas as pd

# Read the CSV file
df = pd.read_csv("login_logs.csv")

# Add new columns for alert, reason, and severity
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

# Save alerts to a new CSV file
alerts = df[df["alert"] == True]
alerts.to_csv("alerts.csv", index=False)
print(f"✅ Done! {len(alerts)} alerts found!")