import pandas as pd
import random
from datetime import datetime, timedelta

users = ["john@corp.com", "ahmed@corp.com", "sara@corp.com", "admin@corp.com"]
countries = ["Egypt", "Egypt", "Egypt", "Russia", "China", "USA"]
ips = ["197.32.10.1", "197.32.10.2", "185.220.101.5", "45.33.32.156", "10.0.0.5"]
devices = ["Windows 11", "MacOS", "Linux", "Unknown"]

rows = []
for i in range(100):
    user = random.choice(users)
    country = random.choice(countries)
    ip = random.choice(ips)
    success = random.choice([True, True, True, False])
    mfa = random.choice([True, False])
    timestamp = datetime.now() - timedelta(minutes=random.randint(1, 10000))

    rows.append({
        "user": user,
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": ip,
        "country": country,
        "device": random.choice(devices),
        "success": success,
        "mfa_used": mfa
    })

df = pd.DataFrame(rows)
df.to_csv("login_logs.csv", index=False)
print(" login_logs.csv created!")
