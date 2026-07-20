import os
import sys
import pwd

def audit_runner_account():
    """
    Performs a defensive security posture check on the active runtime account.
    Identifies misconfigurations regarding user privileges and environment exposure.
    """
    print("[*] Initializing Local User Security Risk Assessment...")
    print("-" * 55)
    
    # 1. Identify active runtime identity configuration
    try:
        uid = os.getuid()
        user_info = pwd.getpwuid(uid)
        username = user_info.pw_name
        current_home = user_info.pw_dir
        print(f"[+] Active Runner Account Detected: '{username}' (UID: {uid})")
    except AttributeError:
        print("[-] System Identification Failed: Non-POSIX compliance (Cannot verify UID).")
        return

    # 2. Risk Evaluation: Superuser Check (Privilege Escalation Risk)
    print("\n[*] Auditing Account Privilege Level...")
    if uid == 0:
        print("[CRITICAL RISK]: The runner account is executing with root/superuser privileges.")
        print("  -> Impact: Any successful code execution exploit grants full control of the host.")
    else:
        print("[+] SECURE: The account is operating as a standard unprivileged user.")

    # 3. Risk Evaluation: Environment Secret Exposure Check
    print("\n[*] Scanning Active Environment Variables for Information Leakage...")
    # List of sensitive substrings that should never be plainly visible in process memory
    risk_keywords = ["SECRET", "TOKEN", "PASSWORD", "PASSWORD", "KEY", "AUTH", "CREDENTIALS"]
    exposed_flags = 0
    
    for key, value in os.environ.items():
        # Cross-reference environment variable keys against defensive keywords
        if any(keyword in key.upper() for keyword in risk_keywords):
            # Flag instances where high-entropy string profiles are attached to unsafe names
            print(f"[WARNING]: Sensitive keyword match found in environment key: '{key}'")
            exposed_flags += 1
            
    if exposed_flags == 0:
        print("[+] SECURE: No highly sensitive identity keyword flags exposed in environment variables.")
    else:
        print(f"  -> Mitigation: Ensure sensitive secrets are masked or injected via secure memory vaults.")

    # 4. Risk Evaluation: Home Directory Write Permissions Check
    print("\n[*] Auditing Home Directory Access Controls...")
    if os.path.exists(current_home):
        # Check if the execution context permits arbitrary filesystem writes to user profile paths
        is_writable = os.access(current_home, os.W_OK)
        if is_writable:
            print(f"[NOTE]: Home directory '{current_home}' permits write access to this process runtime.")
            print("  -> Verification: Ensure configuration profiles (.bashrc, .profile) are root-owned to prevent tampering.")
        else:
            print(f"[+] SECURE: Home directory access controls are strictly constrained.")
    else:
        print("[-] Path Verification Failed: Target directory structure unreachable.")

    print("\n[*] Assessment Complete.")

if __name__ == "__main__":
    audit_runner_account()
