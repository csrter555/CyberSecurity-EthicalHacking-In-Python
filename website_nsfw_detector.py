import urllib.request
import urllib.parse
import re

def advanced_content_filter(target_url):
    """
    Performs a deep multi-layered HTML parse to detect explicit metadata,
    hidden media alternative text, and trailing link structural keywords.
    """
    print(f"[*] Initializing Advanced Content & Link Audit on: {target_url}")
    print("-" * 75)

    request_headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Content-Hardening-Auditor/2.0'
    }

    # Deep-scan keyword list
    explicit_indicators = [
        "nsfw", "adult", "porn", "xxx", "sex", "erotic", "nudity", 
        "naked", "dating", "milf", "lesbian", "anal", "threesome", 
        "hentai", "ebony", "porno", "video", "movies", "cum", "fuck"
    ]

    try:
        req = urllib.request.Request(target_url, headers=request_headers)
        with urllib.request.urlopen(req, timeout=6.0) as response:
            # Read the raw source code (including hidden tags)
            raw_html = response.read().decode('utf-8', errors='ignore').lower()
            
            # Isolated text for verification
            visible_text = re.sub(r'<[^>]+>', ' ', raw_html)
            
            risk_score = 0
            audit_findings = {}

            # PHASE 1: Scan Visible Text Content (Standard weight)
            for keyword in explicit_indicators:
                text_matches = len(re.findall(r'\b' + re.escape(keyword) + r'\b', visible_text))
                if text_matches > 0:
                    audit_findings[keyword] = audit_findings.get(keyword, 0) + text_matches
                    risk_score += min(text_matches * 3, 15)

            # PHASE 2: Behind-The-Scenes Metadata & Source Attribute Tracking (Heavy weight)
            # Attackers/Adult sites hide words inside <img alt="explicit text"> or <a href="/porn-video">
            print("[*] Auditing hidden HTML structural elements and media attributes...")
            
            # Extract all data inside image 'alt' descriptions or source links
            hidden_attributes = re.findall(r'(?:href|src|alt|title)\s*=\s*["\']([^"\']+)["\']', raw_html)
            
            hidden_matches_count = 0
            for attribute_text in hidden_attributes:
                for keyword in explicit_indicators:
                    if keyword in attribute_text:
                        audit_findings[keyword] = audit_findings.get(keyword, 0) + 1
                        hidden_matches_count += 1
                        # Increment risk heavily for hidden layout tags
                        risk_score += 4 

            # Display Forensic Assessment Output
            print(f"[+] Data Analysis Complete. Extracted {len(hidden_attributes)} hidden media attributes.")
            print(f"Calculated Content Risk Score: {min(risk_score, 100)}/100")
            print("=" * 75)

            # Format descriptive reporting list
            detected_summary = [f"'{k}' ({v}x)" for k, v in audit_findings.items()]

            if risk_score >= 50:
                print("[CRITICAL VERDICT]: EXPLICIT / NSFW CONTENT CONFIRMED (Tight Block).")
                print("  -> Administrative Action: Block domain resolution instantly under firewall profile.")
                print(f"  -> Captured Indicators: {', '.join(detected_summary[:8])}...")
            elif risk_score >= 15:
                print("[WARNING VERDICT]: MIXED CONTENT / MATURE SYSTEM SPACE DETECTED.")
                print("  -> Administrative Action: Log active session metrics. Review framework.")
                print(f"  -> Captured Indicators: {', '.join(detected_summary[:5])}")
            else:
                print("[+] SECURE VERDICT: Local page data clears safety validation bounds.")
            print("=" * 75)

    except urllib.error.HTTPError as error:
        print(f"[ERROR]: Target server dropped probe. Status: {error.code}")
    except urllib.error.URLError as error:
        print(f"[ERROR]: Network connectivity loss: {error.reason}")

if __name__ == "__main__":
    # Test your updated logic
    advanced_content_filter("https://github.com")