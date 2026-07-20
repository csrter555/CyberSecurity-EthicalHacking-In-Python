import socket
import sys

def basic_port_scanner(ip_list, port_list, timeout=1.0):
    """
    Scans specified IP addresses for open ports using standard TCP sockets.
    Reports connection status and error codes for defensive network mapping.
    """
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

    target_ports = [22, 80, 443]
    
    basic_port_scanner(target_ips, target_ports)