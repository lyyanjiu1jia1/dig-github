import subprocess, re, os, random


def run_dig(domain):
    try:
        # Run dig with Google's DNS server to avoid malformed packet warning
        output = subprocess.check_output(['dig', '@8.8.8.8', domain]).decode('utf-8')
        print(f"Raw dig output: {repr(output)}")
        
        # Parse the full dig output to extract IP addresses
        ip_lines = []
        for line in output.split('\n'):
            # Look for lines with IP addresses in the ANSWER section
            ip_match = re.search(r'\b\d+\.\d+\.\d+\.\d+\b', line)
            if ip_match and "ANSWER" not in line and ";" not in line:
                ip_lines.append(ip_match.group())
        
        print(f"IP lines extracted: {ip_lines}")
        return ip_lines
    except subprocess.CalledProcessError as e:
        print(f"Subprocess error: {e}")
        return []
    except Exception as e:
        print(f"General error: {e}")
        return []


def update_hosts(ip, domain):
    hosts_path = "/etc/hosts"
    backup_path = hosts_path + ".bak"
    os.system(f"sudo cp {hosts_path} {backup_path}")
    pattern = re.compile(rf"^\s*\d+\.\d+\.\d+\.\d+\s+{domain}\s*$", re.MULTILINE)
    with open(hosts_path, 'r') as f:
        lines = f.readlines()
    
    # Check if domain already exists in hosts file
    domain_exists = any(pattern.match(line) for line in lines)
    
    if not domain_exists:
        # Only add the entry if it doesn't already exist
        new_lines = [line for line in lines if not pattern.match(line)]
        new_lines.append(f"{ip} {domain}\n")
        with open(hosts_path, 'w') as f:
            f.writelines(new_lines)
        os.system("sudo dscacheutil -flushcache")
        print(f"Added {domain} to /etc/hosts with IP {ip}")
    else:
        print(f"{domain} already exists in /etc/hosts")


if __name__ == "__main__":
    domain = "github.com"
    print(f"Resolving domain: {domain}")
    ips = run_dig(domain)
    print(f"IPs found: {ips}")
    if ips:
        # Randomly choose one IP from the list
        selected_ip = random.choice(ips)
        update_hosts(selected_ip, domain)
        print(f"Updated /etc/hosts: {selected_ip} {domain}")
    else:
        print("Failed to resolve github.com")