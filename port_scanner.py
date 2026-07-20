import socket
import sys

def basic_port_scanner(ip_list, port_list, timeout=1.0):
    """
    Scans specified IP addresses for open ports using standard TCP sockets.
    Reports connection status and error codes for defensive network mapping.
    """
    print(f"[*] Script is currently executing on hostname: {socket.gethostname()}")
    print("[*] Initializing Defense Mapping Scan...")
    
    for ip in ip_list:
        print(f"\nScanning Target IP: {ip}")
        print("-" * 35)
        
        for port in port_list:
            
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          
            s.settimeout(timeout)
            
            try:
               
                s.connect((ip, port))
                print(f"[+] SUCCESS: Port {port} is OPEN / Logged Connection established.")
                
               
                s.close()
                
            except socket.timeout:
              
                print(f"[-] FAILED: Port {port} - Error: Connection Timeout.")
                
            except socket.error as err:
                
                print(f"[-] FAILED: Port {port} - Error: {err}")
                
            finally:
               
                del s

if __name__ == "__main__":
    target_ips = ["127.0.0.1", "192.168.1.1"]

    target_ports = [22, 80, 443, 8080, 3306, 3389, 445, 135, 139, 138, 137, 25, 53, 110, 143, 993, 995, 587, 465, 21, 20, 23, 69, 161, 162, 514, 520]
    
    basic_port_scanner(target_ips, target_ports)