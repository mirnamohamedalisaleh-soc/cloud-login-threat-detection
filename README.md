# Cloud Login Threat Detection System

A Python project that analyzes cloud login logs, flags suspicious activity, and generates incident reports automatically.

## Goal
Build a practical detection system that thinks like a SOC analyst.

## What It Does
- Reads login data from a CSV file
- Checks each login against 6 detection rules
- Assigns a severity level to each alert
- Generates a full incident report

## Detection Rules
1. Login from a suspicious country (Russia, China)
2. Login from a suspicious IP address
3. Failed login attempt
4. No MFA used
5. Impossible Travel (same user logs in from two different countries within 60 minutes)
6. Brute Force Detection (3 or more failed logins from the same user)

## Severity Levels
- High = suspicious country, IP, impossible travel, or brute force
- Medium = failed login
- Low = no MFA

## Files
- generate_logs.py = creates sample login data
- detect.py = runs the detection logic
- report.py = generates the incident report
- alerts.csv = flagged logins
- incident_report.txt = final report

## Built With
- Python
- Panda