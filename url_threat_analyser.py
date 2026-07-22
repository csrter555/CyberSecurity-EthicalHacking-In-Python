import urllib.parse
import re

def analyze_link_safety(target_url):
    """
    Performs a defensive structural analysis on a suspicious URL string.
    Identifies common infrastructure indicators associated with token grabbers and IP loggers.
    """
    print(f"[*] Initializing Structural Threat Assessment on URL...")
    print("-" * 65)
    
    # Clean and parse the URL components safely
    parsed_url = urllib.parse.urlparse(target_url.strip())
    domain = parsed_url.netloc.lower()
    path = parsed_url.path.lower()
    query = parsed_url.query.lower()
    
    risk_score = 0
    threat_indicators = []

    # 1. Check for Character Obfuscation (Typosquatting / Lookalike Domains)
   
    if re.search(r'[0-9]{3,}', domain):
        threat_indicators.append("[!] HIGH RISK: Domain contains strings of random numbers (Common in temporary trap hosts).")
        risk_score += 25

    # 2. Check for Known Automated IP-Logging Infrastructure Signatures
    known_loggers = ["iplogger", "grabify", "2no", "blasze", "ps3cf", "yip", "stopify"]
    if any(logger in domain for logger in known_loggers):
        threat_indicators.append("[!] CRITICAL RISK: Matches known commercial IP-logging/tracking infrastructure footprints.")
        risk_score += 60

    # 3. Check for Suspicious Trapping Keywords in Path/Query (Account Harvesting)
   
    harvesting_keywords = ["login", "verify", "secure", "auth", "token", "nsfw", "adult", "teen", "dating", "free-cam"]
    if any(keyword in path or keyword in query for keyword in harvesting_keywords):
        threat_indicators.append(f"[!] WARNING: URL string explicitly utilizes high-manipulation or urgency keywords.")
        risk_score += 15

    # 4. Check for Protocol Mismatches (Lack of Encryption)
    if parsed_url.scheme == "http":
        threat_indicators.append("[!] RISK: Link utilizes unencrypted HTTP protocol. Traffic is vulnerable to interception.")
        risk_score += 10

    # 5. Check for Subdomain Stacking / Redirection Elements
 
    if domain.count('.') > 2:
        threat_indicators.append("[!] WARNING: Deep subdomain stacking detected. Likely masking the real root domain.")
        risk_score += 15

    # Display Assessment Results
    print(f"Target Evaluation Domain: {domain}")
    print(f"Calculated Threat Level Score: {risk_score}/100")
    print("=" * 65)
    
    if risk_score >= 50:
        print("[CRITICAL VERDICT]: HIGH RISK TRAP LINK DETECTED.")
        print("  -> Security Action: Block domain resolution instantly. DO NOT CLICK.")
        for indicator in threat_indicators:
            print(f"     {indicator}")
    elif risk_score >= 15:
        print("[SUSPICIOUS VERDICT]: POTENTIAL CREDENTIAL HARVESTER / RISK PRESENT.")
        print("  -> Security Action: Exercise extreme caution. Verify the root identity.")
        for indicator in threat_indicators:
            print(f"     {indicator}")
    else:
        print("[+] SECURE VERDICT: No common automated link-trapping structures detected.")
        print("  -> Note: Always verify external domain origins manually.")
    print("=" * 65)

if __name__ == "__main__":

    suspicious_link_1 = "http://iplogger.org"
    analyze_link_safety(suspicious_link_1)
    
    print("\n")
    
    suspicious_link_2 = "https://github.com"
    analyze_link_safety(suspicious_link_2)