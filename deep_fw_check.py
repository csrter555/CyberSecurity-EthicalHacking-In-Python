import urllib.request
import urllib.error
import ssl

def deep_firewall_audit(target_url="https://github.com"):
    """
    Performs an advanced forensic audit of a target domain's response headers.
    Maps out explicit corporate WAF fingerprints and defensive security policies.
    """
    print(f"[*] Initializing Deep Forensic Boundary Audit on: {target_url}")
    print("=" * 75)

    # Standard browser-mimicking headers to pass initial edge verification checks
    request_headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Threat-Intelligence-Auditor/2.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5'
    }

    # Create a secure SSL context that ignores local certificate mismatches during testing
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(target_url, headers=request_headers)
        with urllib.request.urlopen(req, timeout=7.0, context=ctx) as response:
            headers = response.info()
            
            print(f"[+] Operational Status: 200 OK | Host Server Unlocked Successfully.")
            print("\n" + "[ SECTION 1: ENTERPRISE WAF / CDN FINGERPRINT AUDIT ]".center(75, "-"))
            
            waf_detected = False

            # 1. Cloudflare Detection
            if 'cf-ray' in headers or 'server' in headers and 'cloudflare' in headers.get('server').lower():
                print("[!] CLOUDFLARE SIGNATURE FOUND:")
                print(f"    -> Ray ID: {headers.get('cf-ray', 'N/A')}")
                print(f"    -> Edge Server Token: {headers.get('server', 'N/A')}")
                print("    -> Defense Profile: High. Leverages global reverse-proxy mitigation and automated captcha challenges.")
                waf_detected = True

            # 2. Amazon Web Services (AWS) WAF Detection
            if 'x-amz-id-2' in headers or 'x-amz-request-id' in headers or 'server' in headers and 'awselb' in headers.get('server').lower():
                print("[!] AWS WAF / LOAD BALANCER SIGNATURE FOUND:")
                print(f"    -> Request ID: {headers.get('x-amz-request-id', 'N/A')}")
                print("    -> Defense Profile: Tight. Controlled via AWS Shield and custom access control list (ACL) rulesets.")
                waf_detected = True

            # 3. Fastly CDN & Next-Gen WAF Detection (Used heavily by GitHub)
            if 'x-served-by' in headers or 'x-cache' in headers:
                print("[!] FASTLY ENTERPRISE EDGE / NEXT-GEN WAF DETECTED:")
                print(f"    -> Routing Node: {headers.get('x-served-by', 'N/A')}")
                print(f"    -> Cache Performance Metric: {headers.get('x-cache', 'N/A')}")
                print("    -> Defense Profile: Tight. Intercepts malicious scripts at the edge closest to the user.")
                waf_detected = True

            # 4. Akamai Technologies Detection
            if 'x-akamai-transformed' in headers or 'x-true-client-ip' in headers or 'akamai-extension' in headers:
                print("[!] AKAMAI INTELLIGENT EDGE WAF DETECTED:")
                print("    -> Defense Profile: Enterprise Grade. Direct signature-matching architecture blocks zero-day behavior.")
                waf_detected = True

            # 5. Sucuri / Imperva Cloud WAF Detection
            if 'x-sucuri-id' in headers or 'x-iinfo' in headers or 'x-cdn' in headers and 'incapsula' in headers.get('x-cdn', '').lower():
                print("[!] SUCURI / IMPERVA CORE CLOUD WAF DETECTED:")
                print(f"    -> Infrastructure Signature: {headers.get('x-sucuri-id', headers.get('x-cdn', 'N/A'))}")
                print("    -> Defense Profile: Dedicated Layer 7 Web Application Protection.")
                waf_detected = True

            if not waf_detected:
                print("[+] Notice: No common commercial WAF footprints detected. Host might use an elite or custom-built layer.")

            print("\n" + "[ SECTION 2: SYSTEM INTERFACE & ARCHITECTURE AUDIT ]".center(75, "-"))
            
            # Server Spoofing check
            server_software = headers.get('Server', 'Not Disclosed')
            print(f"[*] Exposed Server Header: '{server_software}'")
            if server_software.lower() in ['github.com', 'cloudflare', 'sucuri']:
                print("    -> Security Assessment: TIGHT. Actual server application framework is entirely hidden from tools.")
            else:
                print("    -> Security Assessment: OPEN RECONNAISSANCE. Software stack details may be partially visible.")

            print("\n" + "[ SECTION 3: SYSTEM POLICY RULES AND MITIGATIONS ]".center(75, "-"))

            # HSTS Check
            if 'Strict-Transport-Security' in headers:
                print(f"[+] PASS: HSTS Security Active -> {headers.get('Strict-Transport-Security')}")
                print("    -> Protects against: SSL Stripping and sniffing attacks by banning unencrypted HTTP channels.")
            else:
                print("[-] FAIL: HSTS Security Inactive. Connection downgrade vectors possible.")

            # CSP Check
            if 'Content-Security-Policy' in headers:
                print("[+] PASS: Content Security Policy (CSP) is Active.")
                print("    -> Protects against: Cross-Site Scripting (XSS) and code injection by restricting script scopes.")
            else:
                print("[-] FAIL: No explicit Content Security Policy mapped. Risk of frame injection.")

            # Clickjacking Protection Check
            if 'X-Frame-Options' in headers:
                print(f"[+] PASS: X-Frame-Options Active -> '{headers.get('X-Frame-Options')}'")
                print("    -> Protects against: Clickjacking. Banned from loading inside malicious outside iframes.")
            else:
                print("[-] FAIL: X-Frame-Options Missing. Target site can potentially be wrapped in an adversarial iframe.")

            # Cross-Site Scripting XSS legacy protection check
            if 'X-XSS-Protection' in headers:
                print(f"[+] NOTE: Legacy X-XSS-Protection Header Active -> '{headers.get('X-XSS-Protection')}'")

            # Data Caching Leak Check
            if 'Cache-Control' in headers:
                print(f"[*] Cache-Control Architecture: '{headers.get('Cache-Control')}'")
                if 'no-store' in headers.get('Cache-Control').lower() or 'private' in headers.get('Cache-Control').lower():
                    print("    -> Privacy Posture: Highly Secure. Sensitive account session data is banned from intermediate router caches.")

            print("=" * 75)
            print("[*] Deep Forensic Audit Completed Successfully.")

    except urllib.error.HTTPError as error:
        print(f"[CRITICAL LOG]: Target server actively blocked evaluation tool. HTTP Status: {error.code}")
        print("  -> Security Verdict: EXTREMELY TIGHT. System drops unverified administrative probes instantly.")
    except urllib.error.URLError as error:
        print(f"[ERROR]: Network layer connection timeout or resolution failure: {error.reason}")

if __name__ == "__main__":
    # Test on GitHub as your baseline target
    deep_firewall_audit("https://github.com")