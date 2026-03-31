# ===========================================
#   DARK WEB MONITOR & OSINT TOOL
# ===========================================

import urllib.request
import urllib.error
import urllib.parse
import hashlib
import json
import socket
import datetime
import os
import time
import re

REPORT = []
REPORT_FILE = f"osint_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"


def display_banner():
    print("\n" + "="*60)
    print("   DARK WEB MONITOR & OSINT TOOL")
    print("="*60)
    print("   Advanced Cybersecurity Project")
    print("   For educational and ethical use only")
    print("="*60)


def display_menu():
    print("\n  MAIN MENU")
    print("  " + "-"*40)
    print("  [1]  Email Breach Check")
    print("  [2]  Password Exposure Check (safe)")
    print("  [3]  Username OSINT Scanner")
    print("  [4]  IP Reputation Lookup")
    print("  [5]  Domain Intelligence")
    print("  [6]  Phone Number Analyzer")
    print("  [7]  Full OSINT Profile (all-in-one)")
    print("  [8]  View & Save Report")
    print("  [9]  Learn about OSINT & Dark Web")
    print("  [10] Exit")


def log(msg):
    """Add to report log."""
    REPORT.append(msg)


def fetch(url, headers=None, timeout=8):
    """Safe HTTP fetch."""
    try:
        req = urllib.request.Request(url, headers=headers or {
            "User-Agent": "Mozilla/5.0 (OSINT-Tool/1.0)"
        })
        resp = urllib.request.urlopen(req, timeout=timeout)
        return resp.read().decode("utf-8", errors="ignore"), resp.status
    except urllib.error.HTTPError as e:
        return "", e.code
    except Exception:
        return "", 0


def section(title):
    line = "=" * 60
    print(f"\n{line}")
    print(f"  {title}")
    print(line)
    log(f"\n{line}\n  {title}\n{line}")


def result(label, value, flag=""):
    icons = {"ok": "[+]", "warn": "[!]", "bad": "[X]", "info": "[i]", "": "   "}
    icon = icons.get(flag, "   ")
    colors = {"ok": "\033[92m", "warn": "\033[93m", "bad": "\033[91m", "info": "\033[94m", "": "\033[0m"}
    reset = "\033[0m"
    color = colors.get(flag, "")
    line = f"  {icon} {label:<28} {value}"
    print(f"  {color}{icon}{reset} {label:<28} {color}{value}{reset}")
    log(line)


def progress(msg):
    print(f"  ... {msg}", end="\r")


# ─────────────────────────────────────────────────────────────
# 1. EMAIL BREACH CHECK
# ─────────────────────────────────────────────────────────────
def check_email(email):
    section(f"EMAIL BREACH CHECK: {email}")

    # Validate format
    if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
        result("Format", "INVALID EMAIL FORMAT", "bad")
        return

    result("Email", email, "info")
    result("Format", "Valid", "ok")

    # Extract domain info
    domain = email.split("@")[1]
    result("Domain", domain, "info")

    # Check domain MX records
    progress("Checking domain DNS...")
    try:
        ip = socket.gethostbyname(domain)
        result("Domain resolves to", ip, "ok")
    except:
        result("Domain DNS", "Could not resolve", "warn")

    # Check HaveIBeenPwned API (v3 — no key needed for domain check)
    progress("Checking breach databases...")
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}?truncateResponse=false"
    data, status = fetch(url, headers={
        "User-Agent": "OSINT-Educational-Tool",
        "hibp-api-key": ""
    })

    if status == 200:
        try:
            breaches = json.loads(data)
            result("Breach Status", f"FOUND IN {len(breaches)} BREACH(ES)!", "bad")
            for b in breaches[:5]:
                result(f"  Breach", b.get('Name','Unknown'), "bad")
                result(f"  Date", b.get('BreachDate','Unknown'), "warn")
                pwn_classes = ", ".join(b.get('DataClasses', [])[:3])
                result(f"  Exposed data", pwn_classes, "warn")
        except:
            result("Breach Status", "Found in breaches (parse error)", "bad")
    elif status == 404:
        result("Breach Status", "NOT FOUND in known breaches", "ok")
        result("Recommendation", "Stay vigilant, monitor regularly", "info")
    elif status == 401:
        result("Breach Status", "API key required for full check", "warn")
        result("Alternative", "Visit haveibeenpwned.com manually", "info")
    elif status == 429:
        result("Breach Status", "Rate limited - try again in 1 min", "warn")
    else:
        result("Breach Status", f"Could not check (status {status})", "warn")
        result("Manual Check", "https://haveibeenpwned.com", "info")

    # Check for disposable email domains
    disposable = ["mailinator.com", "guerrillamail.com", "temp-mail.org",
                  "throwaway.email", "yopmail.com", "sharklasers.com",
                  "10minutemail.com", "trashmail.com", "fakeinbox.com"]
    if domain.lower() in disposable:
        result("Email Type", "DISPOSABLE / TEMPORARY EMAIL", "bad")
    else:
        result("Email Type", "Regular email domain", "ok")

    # Check common email providers risk
    common = ["gmail.com","yahoo.com","hotmail.com","outlook.com","protonmail.com"]
    if domain.lower() in common:
        result("Provider Risk", "Major provider (commonly targeted)", "warn")
    else:
        result("Provider Risk", "Custom/business domain", "info")


# ─────────────────────────────────────────────────────────────
# 2. PASSWORD EXPOSURE CHECK (k-anonymity — safe!)
# ─────────────────────────────────────────────────────────────
def check_password(password):
    section("PASSWORD EXPOSURE CHECK")
    print("  NOTE: Your password NEVER leaves your machine.")
    print("  Only the first 5 chars of its SHA1 hash are sent.\n")

    # Hash the password
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    result("Password length", str(len(password)), "info")
    result("SHA1 Hash (local)", sha1[:10] + "...", "info")
    result("Prefix sent to API", prefix, "info")

    # Check strength locally
    strength_score = 0
    if len(password) >= 12: strength_score += 2
    elif len(password) >= 8: strength_score += 1
    if re.search(r'[A-Z]', password): strength_score += 1
    if re.search(r'[a-z]', password): strength_score += 1
    if re.search(r'\d', password): strength_score += 1
    if re.search(r'[!@#$%^&*]', password): strength_score += 2

    strength = {0:"VERY WEAK",1:"WEAK",2:"FAIR",3:"MODERATE",4:"STRONG",5:"STRONG",6:"VERY STRONG",7:"EXCELLENT"}.get(strength_score,"UNKNOWN")
    flag = "bad" if strength_score <= 2 else "warn" if strength_score <= 4 else "ok"
    result("Password Strength", strength, flag)

    # Query HIBP Pwned Passwords (k-anonymity model)
    progress("Querying breach database (safely)...")
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    data, status = fetch(url)

    if status == 200:
        hashes = {line.split(":")[0]: int(line.split(":")[1]) for line in data.strip().split("\r\n") if ":" in line}
        if suffix in hashes:
            count = hashes[suffix]
            result("Exposure Status", f"PWNED! Found {count:,} times!", "bad")
            result("Action Required", "CHANGE THIS PASSWORD NOW", "bad")
            if count > 100000:
                result("Risk Level", "EXTREMELY COMMON - Never use this", "bad")
            elif count > 1000:
                result("Risk Level", "Very commonly leaked", "bad")
            else:
                result("Risk Level", "Leaked but less common", "warn")
        else:
            result("Exposure Status", "NOT found in known breaches", "ok")
            result("Note", "Still use a unique password per site", "info")
    else:
        result("API Status", f"Could not reach HIBP API ({status})", "warn")
        result("Manual Check", "https://haveibeenpwned.com/passwords", "info")

    # Common password check
    common_passwords = ["password","123456","qwerty","admin","letmein",
                        "welcome","monkey","dragon","master","iloveyou"]
    if password.lower() in common_passwords:
        result("Common Password", "THIS IS A TOP WORST PASSWORD!", "bad")


# ─────────────────────────────────────────────────────────────
# 3. USERNAME OSINT SCANNER
# ─────────────────────────────────────────────────────────────
def check_username(username):
    section(f"USERNAME OSINT: {username}")
    result("Username", username, "info")
    result("Length", str(len(username)), "info")

    # Platforms to check
    platforms = {
        "GitHub":      f"https://github.com/{username}",
        "GitLab":      f"https://gitlab.com/{username}",
        "Twitter/X":   f"https://twitter.com/{username}",
        "Instagram":   f"https://www.instagram.com/{username}/",
        "Reddit":      f"https://www.reddit.com/user/{username}",
        "TikTok":      f"https://www.tiktok.com/@{username}",
        "Pinterest":   f"https://www.pinterest.com/{username}/",
        "Medium":      f"https://medium.com/@{username}",
        "Dev.to":      f"https://dev.to/{username}",
        "HackerNews":  f"https://news.ycombinator.com/user?id={username}",
        "Keybase":     f"https://keybase.io/{username}",
        "Steam":       f"https://steamcommunity.com/id/{username}",
        "Twitch":      f"https://www.twitch.tv/{username}",
        "YouTube":     f"https://www.youtube.com/@{username}",
        "LinkedIn":    f"https://www.linkedin.com/in/{username}",
    }

    found = []
    not_found = []

    print(f"\n  Scanning {len(platforms)} platforms...\n")
    print(f"  {'PLATFORM':<18} {'STATUS':<12} URL")
    print("  " + "-"*60)

    for platform, url in platforms.items():
        progress(f"Checking {platform}...")
        _, status = fetch(url, timeout=6)
        time.sleep(0.3)  # Be polite

        if status == 200:
            print(f"  \033[92m[FOUND]\033[0m    {platform:<18} {url}")
            log(f"  [FOUND]    {platform:<18} {url}")
            found.append((platform, url))
        elif status == 404:
            print(f"  \033[90m[NOT FOUND]\033[0m {platform:<18}")
            log(f"  [NOT FOUND] {platform}")
            not_found.append(platform)
        elif status == 0:
            print(f"  \033[93m[TIMEOUT]\033[0m  {platform:<18}")
            log(f"  [TIMEOUT]  {platform}")
        else:
            print(f"  \033[93m[UNKNOWN {status}]\033[0m {platform:<18}")
            log(f"  [STATUS {status}] {platform}")

    print(f"\n  {'='*60}")
    result("Profiles found", str(len(found)), "ok" if found else "info")
    result("Not found", str(len(not_found)), "info")

    if len(found) >= 5:
        result("Digital Footprint", "HIGH - Significant online presence", "warn")
    elif len(found) >= 2:
        result("Digital Footprint", "MEDIUM - Some online presence", "info")
    else:
        result("Digital Footprint", "LOW - Minimal online presence", "ok")


# ─────────────────────────────────────────────────────────────
# 4. IP REPUTATION LOOKUP
# ─────────────────────────────────────────────────────────────
def check_ip(ip):
    section(f"IP REPUTATION LOOKUP: {ip}")

    # Validate IP
    parts = ip.split(".")
    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        result("IP Format", "INVALID IP ADDRESS", "bad")
        return

    result("IP Address", ip, "info")

    # Check if private
    private_ranges = [
        ip.startswith("192.168."), ip.startswith("10."),
        ip.startswith("172.16."), ip.startswith("172.17."),
        ip.startswith("127."), ip == "0.0.0.0"
    ]
    if any(private_ranges):
        result("IP Type", "PRIVATE / LOCAL IP", "info")
        result("Note", "Private IPs are not routable on internet", "info")

    # Geolocation via ip-api.com (free, no key)
    progress("Fetching geolocation...")
    geo_data, status = fetch(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,proxy,hosting,query")

    if status == 200:
        try:
            geo = json.loads(geo_data)
            if geo.get("status") == "success":
                result("Country", geo.get("country", "Unknown"), "info")
                result("Region", geo.get("regionName", "Unknown"), "info")
                result("City", geo.get("city", "Unknown"), "info")
                result("ISP", geo.get("isp", "Unknown"), "info")
                result("Organization", geo.get("org", "Unknown"), "info")
                result("AS Number", geo.get("as", "Unknown"), "info")

                if geo.get("proxy"):
                    result("Proxy/VPN", "YES - IP is a proxy/VPN", "warn")
                else:
                    result("Proxy/VPN", "Not detected", "ok")

                if geo.get("hosting"):
                    result("Hosting/DC", "YES - Datacenter/Cloud IP", "warn")
                    result("Risk Note", "Hosting IPs often used for attacks", "warn")
                else:
                    result("Hosting/DC", "Residential/Business IP", "info")
        except:
            result("Geolocation", "Could not parse response", "warn")
    else:
        result("Geolocation", f"Service unavailable ({status})", "warn")

    # Reverse DNS
    progress("Reverse DNS lookup...")
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        result("Reverse DNS", hostname, "info")
        # Check for suspicious patterns
        suspicious_rdns = ["tor", "vpn", "proxy", "anonymous", "scan", "attack"]
        if any(s in hostname.lower() for s in suspicious_rdns):
            result("Hostname Flag", "SUSPICIOUS hostname detected!", "bad")
    except:
        result("Reverse DNS", "No PTR record found", "info")

    # Check AbuseIPDB (public endpoint, limited)
    progress("Checking abuse database...")
    abuse_url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    abuse_data, abuse_status = fetch(abuse_url, headers={
        "Key": "",
        "Accept": "application/json",
        "User-Agent": "OSINT-Tool"
    })

    if abuse_status == 200:
        try:
            abuse = json.loads(abuse_data)
            score = abuse.get("data", {}).get("abuseConfidenceScore", 0)
            reports = abuse.get("data", {}).get("totalReports", 0)
            result("Abuse Score", f"{score}/100", "bad" if score > 50 else "warn" if score > 20 else "ok")
            result("Total Reports", str(reports), "bad" if reports > 10 else "info")
        except:
            pass
    else:
        result("AbuseIPDB", "API key needed for full check", "info")
        result("Manual Check", f"https://www.abuseipdb.com/check/{ip}", "info")

    # Check Shodan hint
    result("Shodan Check", f"https://www.shodan.io/host/{ip}", "info")


# ─────────────────────────────────────────────────────────────
# 5. DOMAIN INTELLIGENCE
# ─────────────────────────────────────────────────────────────
def check_domain(domain):
    section(f"DOMAIN INTELLIGENCE: {domain}")

    # Clean domain
    domain = domain.replace("https://","").replace("http://","").split("/")[0].strip()
    result("Domain", domain, "info")

    # DNS Resolution
    progress("Resolving DNS...")
    try:
        ip = socket.gethostbyname(domain)
        result("IP Address", ip, "ok")
    except socket.gaierror:
        result("DNS Resolution", "FAILED - domain may not exist", "bad")
        return

    # Check common subdomains
    progress("Scanning subdomains...")
    subdomains = ["www", "mail", "ftp", "admin", "api", "dev",
                  "staging", "blog", "shop", "vpn", "remote", "secure"]
    found_subs = []

    print("\n  Subdomain scan:")
    for sub in subdomains:
        try:
            full = f"{sub}.{domain}"
            sub_ip = socket.gethostbyname(full)
            print(f"  \033[92m[FOUND]\033[0m {full:<35} -> {sub_ip}")
            log(f"  [FOUND] {full} -> {sub_ip}")
            found_subs.append((full, sub_ip))
        except:
            pass
        time.sleep(0.1)

    if not found_subs:
        print("  No common subdomains found.")
        log("  No common subdomains found.")

    result("Subdomains found", str(len(found_subs)), "warn" if found_subs else "ok")

    # Check security headers
    progress("Checking security headers...")
    _, status = fetch(f"https://{domain}")
    result("HTTPS Status", f"Status {status}" if status else "Unreachable", "ok" if status == 200 else "warn")

    # Check robots.txt
    progress("Fetching robots.txt...")
    robots, r_status = fetch(f"https://{domain}/robots.txt")
    if r_status == 200 and robots:
        result("robots.txt", "Found - may reveal hidden paths", "warn")
        disallowed = [l.split(": ")[1] for l in robots.split("\n") if l.startswith("Disallow:")]
        for d in disallowed[:5]:
            result(f"  Disallowed", d.strip(), "info")
    else:
        result("robots.txt", "Not found or empty", "info")

    # Check for common sensitive files
    progress("Checking exposed files...")
    sensitive = ["/.env", "/admin", "/wp-admin", "/phpinfo.php",
                 "/.git/config", "/backup.zip", "/config.php"]
    exposed = []
    for path in sensitive:
        _, s = fetch(f"https://{domain}{path}", timeout=4)
        if s == 200:
            exposed.append(path)
            result(f"EXPOSED FILE", path, "bad")
        time.sleep(0.1)

    if not exposed:
        result("Exposed files", "None found in common paths", "ok")

    # Shodan & VirusTotal links
    result("Shodan", f"https://www.shodan.io/search?query={domain}", "info")
    result("VirusTotal", f"https://www.virustotal.com/gui/domain/{domain}", "info")


# ─────────────────────────────────────────────────────────────
# 6. PHONE NUMBER ANALYZER
# ─────────────────────────────────────────────────────────────
def check_phone(phone):
    section(f"PHONE NUMBER ANALYZER: {phone}")

    # Clean number
    clean = re.sub(r'[\s\-\(\)\+]', '', phone)
    result("Input", phone, "info")
    result("Cleaned", clean, "info")

    if not clean.isdigit():
        result("Format", "INVALID - contains non-numeric chars", "bad")
        return

    result("Length", str(len(clean)), "info")

    # Country code detection
    country_codes = {
        "1": "USA / Canada (+1)",
        "44": "United Kingdom (+44)",
        "91": "India (+91)",
        "49": "Germany (+49)",
        "33": "France (+33)",
        "86": "China (+86)",
        "7":  "Russia (+7)",
        "81": "Japan (+81)",
        "61": "Australia (+61)",
        "92": "Pakistan (+92)",
        "971":"UAE (+971)",
        "966":"Saudi Arabia (+966)",
    }

    detected_country = "Unknown"
    for code, country in sorted(country_codes.items(), key=lambda x: len(x[0]), reverse=True):
        if clean.startswith(code):
            detected_country = country
            break

    result("Country Code", detected_country, "info")

    # Format analysis
    if len(clean) == 10:
        result("Format Type", "10-digit (local format, no country code)", "info")
    elif len(clean) == 11:
        result("Format Type", "11-digit (may include country code)", "info")
    elif len(clean) == 12:
        result("Format Type", "12-digit (international format)", "info")
    elif len(clean) < 7:
        result("Format Type", "TOO SHORT - invalid number", "bad")
    else:
        result("Format Type", f"{len(clean)} digits", "info")

    # Carrier pattern (US numbers)
    if clean.startswith("1") and len(clean) == 11:
        area = clean[1:4]
        result("Area Code", area, "info")
        result("Number", f"+1 ({area}) {clean[4:7]}-{clean[7:]}", "info")

    # OSINT links
    result("NumLookup", f"https://www.numlookup.com/+{clean}", "info")
    result("TrueCaller", "https://www.truecaller.com (login required)", "info")
    result("Google Search", f'Search: "{phone}" site:pastebin.com', "info")


# ─────────────────────────────────────────────────────────────
# 7. FULL OSINT PROFILE
# ─────────────────────────────────────────────────────────────
def full_profile():
    section("FULL OSINT PROFILE")
    print("  This runs ALL checks and builds a complete report.\n")

    target_type = input("  Target type - (1) Person  (2) Organization: ").strip()

    email = input("  Email address (or press Enter to skip): ").strip()
    username = input("  Username (or press Enter to skip): ").strip()
    domain = input("  Domain/website (or press Enter to skip): ").strip()
    ip = input("  IP address (or press Enter to skip): ").strip()

    print("\n  Running full profile scan...\n")

    if email:    check_email(email)
    if username: check_username(username)
    if domain:   check_domain(domain)
    if ip:       check_ip(ip)

    section("OSINT PROFILE COMPLETE")
    result("Report entries", str(len(REPORT)), "ok")
    result("Report file", REPORT_FILE, "info")
    save_report()


# ─────────────────────────────────────────────────────────────
# 8. REPORT VIEWER & SAVER
# ─────────────────────────────────────────────────────────────
def save_report():
    if not REPORT:
        print("\n  No data to save yet. Run some checks first!")
        return

    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write(f"OSINT REPORT\n")
        f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Tool: Dark Web Monitor & OSINT Tool\n")
        f.write("="*60 + "\n")
        f.write("\n".join(REPORT))

    print(f"\n  Report saved to: {REPORT_FILE}")
    print(f"  Total entries: {len(REPORT)}")


def view_report():
    section("CURRENT SESSION REPORT")
    if not REPORT:
        print("  No data yet. Run some checks first!")
        return
    for line in REPORT:
        print(line)
    save_report()


# ─────────────────────────────────────────────────────────────
# 9. LEARN MODE
# ─────────────────────────────────────────────────────────────
def learn_mode():
    print("""
  OSINT & DARK WEB EXPLAINED
  ==========================

  WHAT IS OSINT?
  Open Source Intelligence - gathering information
  from publicly available sources.
  NO hacking involved - everything is public data!

  WHERE DOES OSINT DATA COME FROM?
    - Social media profiles
    - Public breach databases
    - WHOIS domain records
    - DNS records
    - Search engines
    - Paste sites (Pastebin, GitHub gists)
    - Forum posts and comments
    - Government public records
    - Job postings (reveal tech stack!)

  WHAT IS THE DARK WEB?
  A part of the internet not indexed by search
  engines, requiring Tor browser to access.
  Used for privacy but also for selling:
    - Stolen credentials
    - Credit card data
    - Personal information
    - Hacking tools and malware

  HOW BREACHES HAPPEN:
    1. Attacker hacks a company database
    2. Millions of emails + passwords are stolen
    3. Data is sold on dark web marketplaces
    4. Other criminals buy it for phishing/fraud
    5. Eventually it leaks publicly on paste sites

  HAVE I BEEN PWNED (HIBP):
  A free service by Troy Hunt that tracks known
  breaches. Contains 12+ billion compromised
  accounts. Uses k-anonymity so your password
  never actually leaves your machine!

  K-ANONYMITY (HOW HIBP WORKS SAFELY):
    1. Your password is hashed: SHA1("hello") = AAF4C6...
    2. Only first 5 chars sent: AAF4C
    3. API returns ALL hashes starting with AAF4C
    4. Your device checks if your full hash is in the list
    5. Server never sees your actual hash!

  OSINT TOOLS USED BY PROFESSIONALS:
    Maltego     - Visual OSINT link analysis
    Shodan      - Search engine for devices/servers
    SpiderFoot  - Automated OSINT framework
    theHarvester- Email and domain harvesting
    Recon-ng    - Modular OSINT framework
    OSINT Framework - osintframework.com

  LEGAL & ETHICAL NOTE:
  OSINT on PUBLIC data is legal.
  Using it to stalk, harass, or defraud = ILLEGAL.
  Always get permission before running OSINT
  on someone else's systems or accounts.
    """)


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────
def main():
    display_banner()
    print("\n  ETHICAL USE NOTICE:")
    print("  Only investigate accounts/systems you OWN")
    print("  or have explicit written permission to test.")
    print("  Unauthorized OSINT on individuals may be illegal.")

    while True:
        display_menu()
        choice = input("\n  Choose an option (1-10): ").strip()

        if choice == "1":
            email = input("\n  Enter email address: ").strip()
            check_email(email)

        elif choice == "2":
            import getpass
            password = getpass.getpass("\n  Enter password to check (hidden): ")
            check_password(password)

        elif choice == "3":
            username = input("\n  Enter username: ").strip()
            check_username(username)

        elif choice == "4":
            ip = input("\n  Enter IP address: ").strip()
            check_ip(ip)

        elif choice == "5":
            domain = input("\n  Enter domain (e.g. example.com): ").strip()
            check_domain(domain)

        elif choice == "6":
            phone = input("\n  Enter phone number: ").strip()
            check_phone(phone)

        elif choice == "7":
            full_profile()

        elif choice == "8":
            view_report()

        elif choice == "9":
            learn_mode()

        elif choice == "10":
            print("\n  Goodbye! Stay safe online!\n")
            break

        else:
            print("\n  Invalid option. Please choose 1-10.")

        input("\n  Press Enter to continue...")


if __name__ == "__main__":
    main()