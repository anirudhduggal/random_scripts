import paramiko
import sys
import argparse

def ssh_login(ip, username, password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(ip, username=username, password=password)
        print(f"Success: Valid credentials for {username}@{ip}" )
        
        #uncomment the lines below and run a command on successful execution
        #stdin, stdout, stderr = ssh.exec_command('whoami')  
        #command_out = stdout.read().decode('utf-8').strip()
        #print(f"Command Executed and results is " + command_out)
        
        
    except paramiko.AuthenticationException:
        print(f"Failed: Invalid credentials for {username}@{ip}")
    except paramiko.SSHException as sshException:
        print(f"Error: Unable to establish SSH connection to {ip}: {sshException}")
    except Exception as e:
        print(f"Error: Exception occurred while connecting to {ip}: {e}")
    finally:
        ssh.close()

def read_ip_addresses(ip_file):
    try:
        with open(ip_file, 'r') as file:
            ips = file.read().splitlines()
            return ips
    except Exception as e:
        print(f"Error: Unable to read IP file {ip_file}: {e}")
        sys.exit(1)

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Check if ssh works and run a command")
    parser.add_argument("ip_address", help="IP address of the remote host")
    parser.add_argument("-u","--username", help="Username for SSH login")
    parser.add_argument("-p", "--password", help="Password for SSH login")
    
    args = parser.parse_args()

    ip_input = str(args.ip_address)
    username = args.username
    password = args.password


    if ip_input.endswith('.txt'):
        ip_addresses = read_ip_addresses(ip_input)
    else:
        ip_addresses = [ip_input]

    for ip in ip_addresses:
        ssh_login(ip, username, password)
