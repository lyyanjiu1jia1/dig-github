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


def update_hosts_multiple(ips, domain):
    hosts_path = "/etc/hosts"
    backup_path = hosts_path + ".bak"
    os.system(f"sudo cp {hosts_path} {backup_path}")
    pattern = re.compile(rf"^\s*\d+\.\d+\.\d+\.\d+\s+{domain}\s*(?:\s*#.*)?$", re.MULTILINE)
    with open(hosts_path, 'r') as f:
        lines = f.readlines()
    
    # Filter out existing entries for this domain
    new_lines = [line for line in lines if not pattern.match(line)]
    
    # Add new entries, using all IPs or up to 2 if there are more
    ips_to_add = ips[:2] if len(ips) > 2 else ips
    for i, ip in enumerate(ips_to_add):
        if i == 0:
            new_lines.append(f"{ip}    {domain}\n")
        else:
            new_lines.append(f"{ip}    {domain}  # 额外添加的备用IP\n")
    
    with open(hosts_path, 'w') as f:
        f.writelines(new_lines)
    os.system("sudo dscacheutil -flushcache")
    print(f"Updated /etc/hosts with {len(ips_to_add)} entries for {domain}")


def update_hosts_for_domain(domain):
    print(f"Resolving domain: {domain}")
    ips = run_dig(domain)
    print(f"IPs found: {ips}")
    if ips:
        update_hosts_multiple(ips, domain)
        for i, ip in enumerate(ips[:2]):
            suffix = "" if i == 0 else " (备用)"
            print(f"Updated /etc/hosts: {ip} {domain}{suffix}")
    else:
        print(f"Failed to resolve {domain}")


if __name__ == "__main__":
    domains = ["github.com", "github.global.ssl.fastly.net"]
    for domain in domains:
        update_hosts_for_domain(domain)