import pandas as pd
from datetime import datetime

# Read alerts
alerts = pd.read_csv("alerts.csv")

# Open report file
report_file = open("incident_report.txt", "w")

report_file.write("=" * 60 + "\n")
report_file.write("       CLOUD LOGIN THREAT DETECTION - INCIDENT REPORT\n")
report_file.write(f"       Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
report_file.write("=" * 60 + "\n\n")

report_file.write(f"Total Alerts Found: {len(alerts)}\n")
report_file.write(f"High Severity: {len(alerts[alerts['severity'] == 'High'])}\n")
report_file.write(f"Medium Severity: {len(alerts[alerts['severity'] == 'Medium'])}\n")
report_file.write(f"Low Severity: {len(alerts[alerts['severity'] == 'Low'])}\n\n")
report_file.write("=" * 60 + "\n\n")

# Write one report per alert
for i, row in alerts.iterrows():
    report_file.write(f"INCIDENT #{i+1}\n")
    report_file.write(f"  User:      {row['user']}\n")
    report_file.write(f"  Time:      {row['timestamp']}\n")
    report_file.write(f"  Source IP: {row['source_ip']}\n")
    report_file.write(f"  Country:   {row['country']}\n")
    report_file.write(f"  Device:    {row['device']}\n")
    report_file.write(f"  Success:   {row['success']}\n")
    report_file.write(f"  MFA Used:  {row['mfa_used']}\n")
    report_file.write(f"  Reason:    {row['reason']}\n")
    report_file.write(f"  Severity:  {row['severity']}\n")
    report_file.write("-" * 60 + "\n\n")

report_file.close()
print("✅ Incident report generated: incident_report.txt")