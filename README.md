# Dark Web Monitor & OSINT Tool

An advanced cybersecurity project for gathering open-source intelligence — for ethical, educational use only.

---

## Project Structure

```

├── osint.py          # main file
└── README.md        # This file
```

---

## Requirements

- Python 3.x
- No extra libraries needed — uses built-in urllib, hashlib, socket

---

## How to Run

```bash
python osint.py
```

---

## Features

| Option | What it does |
|---|---|
| 1. Email Breach Check | Checks if email appeared in known data breaches |
| 2. Password Exposure | Checks if password was leaked (safely via k-anonymity) |
| 3. Username OSINT | Searches 15 platforms for a username |
| 4. IP Reputation | Geolocation, reverse DNS, proxy/VPN detection |
| 5. Domain Intelligence | Subdomains, exposed files, robots.txt, DNS |
| 6. Phone Analyzer | Country detection, format analysis, OSINT links |
| 7. Full Profile | Runs all checks and saves a complete report |
| 8. View Report | Shows and saves everything to a .txt file |
| 9. Learn Mode | Explains OSINT, dark web, and k-anonymity |

---

## How Password Checking Works Safely (K-Anonymity)

Your password NEVER leaves your machine. Here is exactly what happens:

1. Password is hashed locally: SHA1("mypassword") = AAF4C61...
2. Only the first 5 characters are sent to the API: AAF4C
3. The API returns ALL hashes that start with AAF4C (thousands of them)
4. Your device checks locally if your full hash is in the list
5. The server never sees your password or your full hash

This is called k-anonymity and was designed by Troy Hunt (haveibeenpwned.com).

---

## What You Learn

- How OSINT (Open Source Intelligence) works professionally
- How data breaches happen and where stolen data ends up
- K-anonymity — a privacy-preserving protocol used in real security tools
- DNS resolution, reverse DNS, geolocation APIs
- How to build multi-module investigation tools in Python
- The difference between surface web, deep web, and dark web
- How tools like Maltego, Shodan, and SpiderFoot work

---

## Legal & Ethical Notice

OSINT on public data is legal. However:
- Do NOT investigate people without their permission
- Do NOT use findings to harass, stalk, or defraud
- Only run on accounts and systems you own or have written permission to test
- Unauthorized OSINT on individuals may violate privacy laws

---

## Real Professional Tools That Do This

| Tool | What it does |
|---|---|
| Maltego | Visual OSINT link analysis |
| Shodan | Search engine for internet-connected devices |
| SpiderFoot | Automated OSINT framework |
| theHarvester | Email and domain intelligence |
| OSINT Framework | osintframework.com — massive resource list |

