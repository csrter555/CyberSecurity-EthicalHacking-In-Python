import subprocess
import socket
import time

def run_terminal_command(command):
    """Safely executes a system terminal command using Python subprocess."""
    try:
        # Runs the command and waits for it to finish
        result = subprocess.run(command, shell=True, check=True, 
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        return False, e.stderr

def test_local_port(port=8080):
    """Attempts a quick TCP socket connection to verify if a port is reachable."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    try:
        s.connect(('127.0.0.1', port))
        s.close()
        return "OPEN"
    except socket.timeout:
        return "BLOCKED (Timeout)"
    except socket.error:
        return "CLOSED (Refused)"

def main():
    target_port = 8080
    print("[*] Starting Automated Firewall Policy Test...")
    print("-" * 60)

    # Step 1: Check the baseline before the firewall is active
    print(f"[1] Checking initial status of Port {target_port}...")
    initial_status = test_local_port(target_port)
    print(f"    -> Baseline Status: {initial_status}")

    # Step 2: Inject the temporary firewall rule (DROP all packets going to port 8080)
    print(f"\n[2] Injecting temporary firewall rule to BLOCK Port {target_port}...")
    # This iptables command appends (-A) a rule to the INPUT chain to DROP TCP traffic on port 8080
    fw_rule = f"sudo iptables -A INPUT -p tcp --dport {target_port} -j DROP"
    
    success, message = run_terminal_command(fw_rule)
    if not success:
        print(f"[CRITICAL ERROR]: Could not inject firewall rule. Reason: {message.strip()}")
        print("-> Note: Linux firewall manipulation requires administrator (sudo) privileges.")
        return

    print("[+] Firewall Rule Successfully Injected into System Kernel.")

    # Step 3: Run the vulnerability/connectivity scan while the firewall is live
    print(f"\n[3] Testing network vulnerability (Scanning Port {target_port})...")
    time.sleep(1) # Give the kernel a second to process the rule
    test_status = test_local_port(target_port)
    print(f"    -> Result during test: Port is {test_status}")
    
    if test_status == "BLOCKED (Timeout)":
        print("    -> SUCCESS: The temporary firewall completely mitigated the vulnerability risk!")
    else:
        print("    -> WARNING: The firewall rule failed to block the traffic.")

    # Step 4: Tear down the firewall rule to restore standard network configuration
    print(f"\n[4] Tearing down temporary rule to clean up system records...")
    # This iptables command deletes (-D) the exact rule we just created
    cleanup_rule = f"sudo iptables -D INPUT -p tcp --dport {target_port} -j DROP"
    
    cleanup_success, cleanup_message = run_terminal_command(cleanup_rule)
    if cleanup_success:
        print("[+] System Cleaned. Temporary firewall rules wiped successfully.")
    else:
        print(f"[ERROR]: Failed to remove firewall rule automatically: {cleanup_message}")

if __name__ == "__main__":
    main()