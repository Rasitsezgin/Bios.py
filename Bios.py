import requests
import socket
import whois
import subprocess
import dns.resolver
import sys
import json
import ipaddress
import re
from functools import wraps

# --- Configuration ---
# API keys should ideally be loaded from environment variables or a config file
# rather than hardcoded for security and flexibility.
# For demonstration, they are kept here, but remember to replace 'YOUR_CENSYS_API_KEY'
# and 'YOUR_SHODAN_API_KEY' with your actual keys.
CENSYS_API_KEY = 'YOUR_CENSYS_API_KEY'
SHODAN_API_KEY = 'YOUR_SHODAN_API_KEY'

# --- Utility Decorators ---

def handle_errors(func):
    """
    A decorator to gracefully handle exceptions for functions performing external calls.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except requests.exceptions.RequestException as e:
            return f"Network Error for {func.__name__}: {e}"
        except subprocess.CalledProcessError as e:
            return f"Subprocess Error for {func.__name__}: {e.output.decode().strip()}"
        except dns.resolver.NXDOMAIN:
            return f"DNS Error for {func.__name__}: Domain not found."
        except dns.resolver.NoAnswer:
            return f"DNS Error for {func.__name__}: No DNS records found for the query type."
        except dns.exception.Timeout:
            return f"DNS Error for {func.__name__}: DNS query timed out."
        except socket.gaierror as e:
            return f"Socket Error for {func.__name__}: Could not resolve host ({e})."
        except whois.parser.PywhoisError as e:
            return f"Whois Error for {func.__name__}: {e}"
        except Exception as e:
            return f"An unexpected error occurred in {func.__name__}: {e}"
    return wrapper

# --- Core Information Gathering Functions ---

@handle_errors
def get_ip_from_domain(domain):
    """
    Resolves a domain name to its IPv4 address.
    Returns the IP address as a string or an error message.
    """
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        return "Could not resolve domain to an IP address."

@handle_errors
def censys_search(query):
    """
    Performs a search on Censys for hosts matching the query.
    Returns parsed JSON data or an error message.
    """
    if CENSYS_API_KEY == 'YOUR_CENSYS_API_KEY':
        return "Censys API key not configured. Please set CENSYS_API_KEY."

    # Censys API v2 uses POST for host search
    url = 'https://search.censys.io/api/v2/hosts/search'
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {CENSYS_API_KEY}'
    }
    data = {'query': query, 'per_page': 5} # Limit results for brevity

    response = requests.post(url, headers=headers, data=json.dumps(data), timeout=15)
    response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)
    return response.json()

@handle_errors
def shodan_search(query):
    """
    Performs a search on Shodan for hosts matching the query.
    Returns parsed JSON data or an error message.
    """
    if SHODAN_API_KEY == 'YOUR_SHODAN_API_KEY':
        return "Shodan API key not configured. Please set SHODAN_API_KEY."

    api = shodan.Shodan(SHODAN_API_KEY)
    try:
        results = api.search(query)
        return results
    except shodan.APIError as e:
        return f"Shodan API Error: {e}"

@handle_errors
def dns_lookup(target_domain, record_type='A'):
    """
    Performs DNS lookups for various record types (A, AAAA, NS, MX, TXT, CNAME).
    Returns a list of records or an error message.
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    results = []
    if record_type == 'A':
        answers = resolver.resolve(target_domain, 'A')
        results.extend([str(r) for r in answers])
    elif record_type == 'AAAA':
        answers = resolver.resolve(target_domain, 'AAAA')
        results.extend([str(r) for r in answers])
    elif record_type == 'NS':
        answers = resolver.resolve(target_domain, 'NS')
        results.extend([str(r) for r in answers])
    elif record_type == 'MX':
        answers = resolver.resolve(target_domain, 'MX')
        results.extend([f"{str(r.exchange)} (Priority: {r.preference})" for r in answers])
    elif record_type == 'TXT':
        answers = resolver.resolve(target_domain, 'TXT')
        results.extend([str(r).strip('"') for r in answers])
    elif record_type == 'CNAME':
        answers = resolver.resolve(target_domain, 'CNAME')
        results.extend([str(r) for r in answers])
    else:
        return f"Unsupported DNS record type: {record_type}"

    return results if results else f"No {record_type} records found for {target_domain}."

@handle_errors
def port_scan_nmap(target_ip, top_ports=100):
    """
    Performs a port scan using Nmap for common ports.
    Requires Nmap to be installed on the system.
    Returns Nmap output as a string or an error message.
    """
    print(f"Running Nmap scan on {target_ip} for top {top_ports} ports. This may take a moment...")
    try:
        # -F: Fast mode (scans the 100 most common ports)
        # -T4: Aggressive timing (faster but can be detected)
        # --open: Only show open ports
        command = ['nmap', '-F', '-T4', '--open', target_ip] # Removed --top-ports for simplicity and common usage
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=120)
        return result.stdout
    except subprocess.TimeoutExpired:
        return f"Nmap scan timed out for {target_ip}."

@handle_errors
def detect_cms(url):
    """
    Attempts to detect common CMS platforms (WordPress, Joomla, Drupal)
    by checking specific file paths and response headers/content.
    Returns detected CMS or 'Unknown'.
    """
    cms_signatures = {
        'WordPress': ['/wp-login.php', '/wp-admin/', '/wp-content/'],
        'Joomla': ['/administrator/', '/media/'],
        'Drupal': ['/core/misc/', '/sites/all/modules/'],
    }

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        # Check headers for 'X-Powered-By' or 'Server'
        if 'X-Powered-By' in response.headers:
            if 'Joomla' in response.headers['X-Powered-By']:
                return "Joomla"
            if 'Drupal' in response.headers['X-Powered-By']:
                return "Drupal"
        if 'X-Generator' in response.headers:
            if 'WordPress' in response.headers['X-Generator']:
                return "WordPress"

        # Check content for common CMS patterns
        for cms, paths in cms_signatures.items():
            for path in paths:
                test_url = f"{url.rstrip('/')}{path}"
                try:
                    head_response = requests.head(test_url, timeout=5, allow_redirects=True)
                    if head_response.status_code == 200:
                        return cms
                    elif head_response.status_code == 301 or head_response.status_code == 302:
                        # Follow redirects for deeper check if necessary
                        get_response = requests.get(test_url, timeout=5)
                        if cms == 'WordPress' and 'wp-login.php' in get_response.url:
                            return cms
                except requests.RequestException:
                    continue
        return "CMS could not be confidently detected."
    except requests.exceptions.RequestException:
        return "Unable to connect to the target URL to detect CMS."

@handle_errors
def whois_lookup(target_identifier):
    """
    Performs a WHOIS lookup for a domain or IP address.
    Returns parsed WHOIS data or an error message.
    """
    return whois.whois(target_identifier)

@handle_errors
def detect_honeypot_http(ip_address):
    """
    Attempts to detect honeypots by analyzing HTTP response headers and content.
    This is a very basic detection and might not be accurate.
    More advanced honeypot detection would involve behavioral analysis.
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    try:
        response = requests.get(f'http://{ip_address}', headers=headers, timeout=5, allow_redirects=True)
        response.raise_for_status()

        # Basic honeypot indicators (can be easily bypassed)
        honeypot_keywords = ['honeypot', 'dionaea', 'kippo', 'cowrie', 'glastopf', 'elasticpot']
        for keyword in honeypot_keywords:
            if keyword in response.text.lower() or keyword in str(response.headers).lower():
                return "Potential honeypot detected based on HTTP response content or headers."

        # Check for unusual server banners (e.g., specific honeypot software)
        if 'Server' in response.headers:
            server_banner = response.headers['Server'].lower()
            if 'dionaea' in server_banner or 'kippo' in server_banner:
                return "Potential honeypot detected (unusual server banner)."

        return "No obvious honeypot indicators found via HTTP."
    except requests.exceptions.Timeout:
        return "Honeypot detection timed out (might indicate a slow/unresponsive server)."
    except requests.exceptions.ConnectionError:
        return "Could not connect to the target for honeypot detection."


@handle_errors
def find_subdomains_passive(domain):
    """
    Uses passive subdomain enumeration techniques (e.g., from online sources).
    This example uses crt.sh (Certificate Transparency logs).
    For more comprehensive results, consider tools like Amass or Subfinder
    which might require external installation or API keys.
    """
    print(f"Searching for subdomains for {domain} using passive sources (crt.sh)...")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    response = requests.get(url, timeout=15)
    response.raise_for_status()
    data = response.json()

    subdomains = set()
    for entry in data:
        name = entry.get('common_name')
        if name and name.endswith(f'.{domain}') and not name.startswith('*.'):
            subdomains.add(name)
        # Also check for subject_alt_names
        sans = entry.get('name_value', '').split('\n')
        for san in sans:
            if san.endswith(f'.{domain}') and not san.startswith('*.'):
                subdomains.add(san)

    return list(subdomains) if subdomains else f"No subdomains found for {domain} via crt.sh."

@handle_errors
def reverse_ip_lookup(ip_address):
    """
    Performs a reverse DNS lookup to find the domain name associated with an IP address.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except socket.herror:
        return "No reverse DNS entry found for this IP address."

@handle_errors
def detect_technologies_wappalyzer(url):
    """
    Detects web technologies using requests to analyze headers and content.
    This is a simplified approach. For more robust detection, consider using
    a dedicated library like `Wappalyzer` (which would need installation
    and might have its own dependencies) or integrating with online services.
    """
    print(f"Attempting to detect web technologies for {url}...")
    detected_tech = set()
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        # Check headers
        if 'Server' in response.headers:
            detected_tech.add(f"Server: {response.headers['Server']}")
        if 'X-Powered-By' in response.headers:
            detected_tech.add(f"Powered By: {response.headers['X-Powered-By']}")
        if 'Content-Type' in response.headers:
            if 'php' in response.headers['Content-Type'].lower():
                detected_tech.add("PHP")
            if 'asp.net' in response.headers['Content-Type'].lower():
                detected_tech.add("ASP.NET")

        # Check for common CMS/frameworks in content (very basic)
        if 'wordpress' in response.text.lower() or 'wp-content' in response.text.lower():
            detected_tech.add("WordPress")
        if 'joomla' in response.text.lower() or 'joomla.css' in response.text.lower():
            detected_tech.add("Joomla")
        if 'drupal' in response.text.lower() or 'drupal.css' in response.text.lower():
            detected_tech.add("Drupal")
        if '<html lang="en-us"' in response.text.lower() and 'hugo' in response.text.lower():
            detected_tech.add("Hugo (Static Site Generator)")
        if 'react-root' in response.text.lower() or 'id="root"' in response.text.lower(): # Basic check for React apps
            detected_tech.add("ReactJS")
        if 'vue.js' in response.text.lower() or 'id="app"' in response.text.lower(): # Basic check for Vue.js apps
            detected_tech.add("Vue.js")

        return list(detected_tech) if detected_tech else "No specific web technologies detected via basic analysis."

    except requests.exceptions.RequestException as e:
        return f"Error detecting technologies: {e}"

# --- Presentation and User Interface ---

def print_section_header(title):
    """Prints a formatted section header."""
    print(f"\n{'-' * (len(title) + 4)}")
    print(f"| {title} |")
    print(f"{'-' * (len(title) + 4)}")

def display_results(title, result):
    """Displays results in a consistent format."""
    print_section_header(title)
    if isinstance(result, dict) or isinstance(result, list):
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(result)

def menu():
    """Prints the main menu options."""
    print("\n--- Reconnaissance Tool Menu ---")
    print("1. DNS Information (A, AAAA, NS, MX, TXT, CNAME records)")
    print("2. WHOIS Lookup")
    print("3. Port Scan (using Nmap)")
    print("4. CMS Detection")
    print("5. Web Technology Detection")
    print("6. Subdomain Enumeration (Passive)")
    print("7. Reverse IP Lookup")
    print("8. Honeypot Detection (Basic HTTP Analysis)")
    print("9. Censys Search (requires API Key)")
    print("10. Shodan Search (requires API Key)")
    print("0. Perform All Scans")
    print("q. Quit")
    print("------------------------------")

def get_target_input():
    """Gets and validates target input from the user."""
    while True:
        target = input("Enter target (domain or IP address): ").strip()
        if not target:
            print("Target cannot be empty. Please try again.")
            continue
        return target

def is_valid_ip(ip_string):
    """Checks if a string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False

def is_valid_domain(domain_string):
    """Basic check for a valid domain name."""
    # This regex is a simple check, not exhaustive for all TLDs/IDNs.
    if len(domain_string) > 253:
        return False
    if domain_string.endswith('.'):
        domain_string = domain_string[:-1] # strip trailing dot
    return re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$", domain_string)

# --- Main Function ---

def main():
    """Main function to run the reconnaissance tool."""
    print("Welcome to the Enhanced Reconnaissance Tool!")
    print("Ensure Nmap is installed for port scanning functionality.")

    while True:
        menu()
        choice = input('Enter your choice: ').strip().lower()

        if choice == 'q':
            print("Exiting tool. Goodbye!")
            sys.exit(0)

        if choice not in ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '0']:
            print('Invalid choice. Please enter a valid option from the menu.')
            continue

        target = get_target_input()

        # Determine if target is IP or domain for specific functions
        is_ip = is_valid_ip(target)
        is_domain = is_valid_domain(target)
        target_ip = None # To store resolved IP if target is a domain

        if not is_ip and not is_domain:
            print(f"'{target}' does not appear to be a valid domain or IP address. Some functions may fail.")
            # Attempt to resolve if it looks like a potential domain
            potential_ip = get_ip_from_domain(target)
            if "Error" not in str(potential_ip):
                target_ip = potential_ip
                is_ip = True # Treat it as an IP for IP-specific functions
                print(f"Resolved '{target}' to IP: {target_ip}")
            else:
                print(f"Could not resolve '{target}' to an IP address.")

        elif is_domain:
            potential_ip = get_ip_from_domain(target)
            if "Error" not in str(potential_ip):
                target_ip = potential_ip
            else:
                print(f"Warning: Could not resolve IP for domain '{target}'. Some IP-dependent functions may not work.")


        # Execute chosen function(s)
        if choice == '1' or choice == '0':
            display_results("DNS A Records", dns_lookup(target, 'A'))
            if is_domain: # Only check for AAAA if it's a domain, as IPs are specific
                display_results("DNS AAAA Records", dns_lookup(target, 'AAAA'))
            display_results("DNS NS Records", dns_lookup(target, 'NS'))
            display_results("DNS MX Records", dns_lookup(target, 'MX'))
            display_results("DNS TXT Records", dns_lookup(target, 'TXT'))
            display_results("DNS CNAME Records", dns_lookup(target, 'CNAME'))

        if choice == '2' or choice == '0':
            display_results("WHOIS Lookup", whois_lookup(target))

        if choice == '3' or choice == '0':
            if target_ip:
                display_results("Port Scan (Nmap)", port_scan_nmap(target_ip))
            elif is_ip:
                display_results("Port Scan (Nmap)", port_scan_nmap(target))
            else:
                print("Skipping Port Scan: Target is not a valid IP and could not be resolved.")

        if choice == '4' or choice == '0':
            if is_domain:
                display_results("CMS Detection", detect_cms(f"http://{target}"))
            else:
                print("Skipping CMS Detection: Target is an IP, not a domain.")

        if choice == '5' or choice == '0':
            if is_domain:
                display_results("Web Technology Detection", detect_technologies_wappalyzer(f"http://{target}"))
            else:
                print("Skipping Web Technology Detection: Target is an IP, not a domain.")

        if choice == '6' or choice == '0':
            if is_domain:
                display_results("Subdomain Enumeration (Passive)", find_subdomains_passive(target))
            else:
                print("Skipping Subdomain Enumeration: Target is an IP, not a domain.")

        if choice == '7' or choice == '0':
            if target_ip:
                display_results("Reverse IP Lookup", reverse_ip_lookup(target_ip))
            elif is_ip:
                display_results("Reverse IP Lookup", reverse_ip_lookup(target))
            else:
                print("Skipping Reverse IP Lookup: Target is not a valid IP and could not be resolved.")

        if choice == '8' or choice == '0':
            if target_ip:
                display_results("Honeypot Detection (Basic HTTP)", detect_honeypot_http(target_ip))
            elif is_ip:
                display_results("Honeypot Detection (Basic HTTP)", detect_honeypot_http(target))
            else:
                print("Skipping Honeypot Detection: Target is not a valid IP and could not be resolved.")

        if choice == '9' or choice == '0':
            display_results("Censys Search Results", censys_search(target))

        if choice == '10' or choice == '0':
            display_results("Shodan Search Results", shodan_search(target))

        input("\nPress Enter to return to the main menu...")

if __name__ == "__main__":
    main()
