import urllib.request
import urllib.error

def audit_github_firewall():
    target_url = "https://github.com"
    print(f"[*] Initializing Boundary Audit on: {target_url}")
    print("-" * 65)
    request_headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Systems-Defense-Auditor/1.0'
    }
    try:
        req = urllib.request.Request(target_url, headers=request_headers)
        with urllib.request.urlopen(req, timeout=5.0) as response:
            status_code = response.getcode()
            headers = response.info()
            print(f"[+] Server Connection Established Successfully. Status: {status_code}")
            print("\n[*] Analyzing Front-Facing Infrastructure Signatures...")
            print("=" * 65)
            has_waf = False
            if 'X-Served-By' in headers or 'X-Cache' in headers:
                print("[DETECTION]: Fastly Enterprise CDN/Edge Architecture detected.")
                print("  -> Signature Found:", headers.get('X-Served-By', 'N/A'))
                has_waf = True
            if 'Server' in headers:
                server_software = headers.get('Server')
                print(f"[DETECTION]: Server masking signature: '{server_software}'")
                if server_software == 'GitHub.com':
                    print("  -> Defense Posture: Tight. Server software string is completely spoofed.")
                    has_waf = True
            if 'Strict-Transport-Security' in headers:
                print("[DETECTION]: HSTS (Strict Transport Security) Policy is ACTIVE.")
                print("  -> Security Policy: Enforces encrypted HTTPS connections, blocking downgrade vectors.")
            if 'Content-Security-Policy' in headers:
                print("[DETECTION]: Content Security Policy (CSP) headers present.")
                print("  -> Security Policy: Restricts rogue script executions on the host frame.")
            print("=" * 65)
            if has_waf:
                print("\n[+] FINAL posturing: GitHub's external boundary is heavily protected (Tight).")
                print("    It completely obscures its architecture and filters traffic using edge nodes.")
            else:
                print("\n[-] FINAL posturing: No standard edge security signatures detected.")
    except urllib.error.URLError as error:
        print(f"[CRITICAL]: Boundary check failed to execute. Reason: {error}")
if __name__ == "__main__":
    audit_github_firewall()