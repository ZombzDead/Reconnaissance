#!/bin/python
from curses import echo
import os
import ipaddress
import subprocess
import socket
import sys
import shutil
from webbrowser import get



INSTALL_DIR="/usr/share/Zombz_Recon"
LOOT_DIR="$INSTALL_DIR/Pawns/"
dns_dictionary = "/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt"
dictionary = "/usr/share/seclists/Discovery/Web-Content/dirsearch.txt"
exclude_status = "404,403,401,503"


class TargetIP:
    def __init__(self, addr):
        self.address = addr
        self.hostname = []
        self.ports = []
        self.asn = ""
        self.asn_name = ""
        self.whois = []
        self.server = ""
        self.vulns = []
        self.cidr = ""
        self.location = ""
        self.country = ""

class Target:
    def __init__(self):
        self.primary_domain = ""
        self.subdomains = []
        self.orgName = ""
        self.dnsrecords = []
        self.buckets = []
        self.mx = None
        self.spf = None
        self.dmarc = []
        self.dmarc_status = ""
        self.emails = []
        self.guessed_emails = []
        self.creds = []
        self.hashes = []
        self.breaches = {}
        self.employees = []
        self.pattern = "{f}{last}"  # Default Email Pattern
        self.urls = []
        self.ipv4 = False
        self.resolved_ips = []

class MasterSwitch:
    def __init__(self):
        self.shodan = True
        self.dnsdumpster = True
        self.screencshot = True
        self.webscraper = True
        self.stealth = False
        self.verbose = False

def target_domain(input_domain):
     input_domain = input_domain.replace("\n","")
     if not input_domain:
        return 0
     if (input_domain):
          if ipaddress.ip_address(input_domain):
               print(input_domain)
    
def target_ip_address(target_list, IP):
    tmp = TargetIP(IP)

    if ipaddress.ip_address(IP).is_private:
        return 0
    
    for keys in target_list.keys():
         for x in target_list[keys].resolved_ips:
              if(IP == x.address):
                   print("info", (IP),1)
                   return 0
    if domain:
        domain = socket.gethostname(IP)
        try:
            target_list[domain].resolved_ips.append(tmp)
        except: print("Unable to get Domain")
        return None
    
#COLORS
RED = "\033[31m"
GREEN = "\033[1;32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[95m"
CYAN = "\033[36m"
BOLD = "\033[1m"
NORMAL = "\033[0m"

##############################################
############### PASSIVE RECON ################
##############################################
def passive_recon(domain):
        print("\n")
        print(f"{BOLD}{GREEN}[*] STARTING FOOTPRINTING{NORMAL}\n")
        print(f"{BOLD}{GREEN}[*] TARGET URL:{YELLOW} {domain} {NORMAL}\n")   
        print(f"{BOLD}{GREEN}[*] TARGET IP ADDRESS:\n {YELLOW} {target_ip_address} {NORMAL}\n")
            
        os.chdir('Pawns')

        if os.path.isdir(domain):
                os.system(f"rm -Rf {domain}")
        os.mkdir("Passive_Recon")
        os.chdir("Passive_Recon")
            
        print(f"\n{BOLD}{GREEN}[+] Checking if the target is alive...{NORMAL}\n")
        try:
                subprocess.check_output(['ping', '-c', '1', '-W', '1', {domain}], stderr=subprocess.STDOUT)
                print(f"\n{BOLD}{YELLOW}{domain}{NORMAL} is alive and well!{NORMAL}\n") # type: ignore
        except subprocess.CalledProcessError:
                print(f"\n{BOLD}{YELLOW}{domain}{RED} is dead, unfortunately.{NORMAL}\n") # type: ignore

        print(f"\n{BOLD}{GREEN}[+] Whois Lookup{NORMAL}\n")
        print(f"{NORMAL}{CYAN}Searching domain name details, contact details of domain owner, domain name servers, netRange, domain dates, expiry records, records last updated...{NORMAL}\n")
        whois_result = subprocess.check_output (['whois', {domain}]).decode()
        with open('whois.txt', 'w') as f:
                f.write(whois_result)
        print(whois_result)

        print(f"\n{BOLD}{GREEN}[+] Nslookup {NORMAL}\n")
        print(f"{NORMAL}{CYAN}Searching DNS Queries...{NORMAL}\n")
        nslookup_result = subprocess.check_output(['nslookup', {domain}]).decode()
        with open ('nslookup.txt', 'w') as f:
                f.write(nslookup_result)
        print(nslookup_result)
                
        print(f"\n{BOLD}{GREEN}[+] Nslookup Text Discovery {NORMAL}\n")
        print(f"{NORMAL}{CYAN}Searching DNS Queries...{NORMAL}\n")
        nslookup_txt_result = subprocess.check_output(['nslookup', '-type=TXT', {domain}]).decode()
        with open ('nslookup_DiscoveredTexts.txt', 'w') as f:
                f.write(nslookup_txt_result)
        print(nslookup_txt_result)
            
        print(f"\n{BOLD}{GREEN}[+] DNS Recon {NORMAL}\n")
        print(f"{NORMAL}{CYAN}DNS Reconnaissance...{NORMAL}\n")
        dnsrecon_result = subprocess.check_output(['sudo', 'dnsrecon', '-d', {domain}]).decode()
        with open('dnsrecon.txt', 'w') as f:
                f.write(dnsrecon_result)
        print(dnsrecon_result)

        print(f"\n{BOLD}{GREEN}[+] DNS Enum {NORMAL}\n")
        print(f"{NORMAL}{CYAN}DNS Enumeration...{NORMAL}\n")
        dnsenum_result = subprocess.check_output(['dnsenum', {domain}]).decode() 
        with open ('dnsenum.txt', 'w') as f:
                f.write(dnsenum_result)
        print(dnsenum_result)

        print(f"\n{BOLD}{GREEN}[+] DNSDumpster Search {NORMAL}\n")
        print(f"{NORMAL}{CYAN}Searching domains to discover hosts related to the domain {NORMAL}\n")
        dnsdumpster_result = subprocess.check_output(['python3', '/opt/tools/Zombz_Recon/Repositories/dnsdumpster/dnsdumpster.py', '-d', {domain}]).decode()
        with open('dnsdumpster.txt', 'w') as f:
                f.write(dnsdumpster_result)
                # Assuming convert command is available in the environment
        os.system(f"echo '{dnsdumpster_result}' | convert label:@- dnsdumpster.png")

        print(f"\n{GREEN}[+] MXRecord Lookup {NORMAL}\n")
        print(f"{NORMAL}{CYAN}Checking SPF and DMARC record...{NORMAL}\n")
        mxrecord_result = subprocess.check_output(['mailspoof', '-d', {domain}]).decode()
        with open('mxrecord.txt', 'w') as f:
                f.write(mxrecord_result)
        print(mxrecord_result)

        print(f"\n{BOLD}{GREEN}[+] WhatWeb {NORMAL}\n")
        print(f"{NORMAL}{CYAN}Searching platform, type of script, google analytics, web server platform, IP address, country, server headers, cookies...{NORMAL}\n")
        whatweb_result = subprocess.check_output(['whatweb', {domain}]).decode()
        with open('whatweb.csv', 'w') as f:
                f.write(whatweb_result)
        print(whatweb_result)

        print(f"\n{BOLD}{GREEN}[+] SSL Scan {NORMAL}\n")
        print(f"{NORMAL}{CYAN}Collecting SSL/TLS information...{NORMAL}\n")
        sslscan_result = subprocess.check_output(['sslscan', '-t', {domain}]).decode()
        with open('ssl_scan.txt', 'w') as f:
                f.write(sslscan_result)
        print(sslscan_result)

        print(f"\n{BOLD}{GREEN}[+] Security Header Check {NORMAL}\n")
        print(f"{NORMAL}{CYAN}Collecting Security Headers...{NORMAL}\n")
        shcheck_https_result = subprocess.check_output(['shcheck.py', f'https://{domain}', '-i', '-x']).decode()
        with open('shcheck_https.txt', 'w') as f:
                f.write(shcheck_https_result)
        print(shcheck_https_result)

        shcheck_http_result = subprocess.check_output(['shcheck.py', f'http://{domain}', '-i', '-x']).decode()
        with open('shcheck_http.txt', 'w') as f:
                f.write(shcheck_http_result)
        print(shcheck_http_result)

        print(f"\n{BOLD}{GREEN}[+] CMSeek {NORMAL}\n")
        print(f"{NORMAL}{CYAN}Collecting CMS Detection & Exploitation Suite...{NORMAL}\n")
        cmseek_result = subprocess.check_output(['python3', '/opt/tools/Zombz_Recon/Repositories/CMSeeK/cmseek.py', '-u', {domain}, '--follow-redirect']).decode()
        print(cmseek_result)

        print(f"\n{BOLD}{GREEN}[+] Shodan Query {NORMAL}\n")
        print(f"{NORMAL}{CYAN}Collecting Organization Information from Shodan...{NORMAL}\n")
        shodan_result = get(f"https://api.shodan.io/{domain}?key={{}}").text
        with open('shodan_org.txt', 'w') as f:
                f.write(shodan_result)
        print(shodan_result)

        print(f"\n{BOLD}{GREEN}[+] TheHarvester {NORMAL}\n")
        print(f"{NORMAL}{CYAN}Searching emails, subdomains, hosts, employee names...{NORMAL}\n")
        theharvester_result = subprocess.check_output(['theHarvester', '-d', {domain}, '-b', 'all', '-l', '500']).decode()
        with open('theHarvester.txt', 'w') as f:
                f.write(theharvester_result)
        print(theharvester_result)

        print(f"\n{BOLD}{GREEN}[+] CloudEnum {NORMAL}\n")
        print(f"{NORMAL}{CYAN}Searching public resources in AWS, Azure, and Google Cloud....{NORMAL}\n")
        cloudenum_result = subprocess.check_output(['python3', '/opt/tools/Zombz_Recon/Repositories/cloud_enum/cloud_enum.py', '-k', {domain}]).decode()
        with open('CloudEnum.txt', 'w') as f:
                f.write(cloudenum_result)
        print(cloudenum_result)

        print(f"\n{BOLD}{GREEN}[+] Sublist3r {NORMAL}\n")
        print(f"{NORMAL}{CYAN}Enumerates Subdomains of websites utilizing OSINT...{NORMAL}\n")
        sublist3r_result = subprocess.check_output(['sublist3r', '-d', {domain}]).decode()
        with open('sud_domains.txt', 'w') as f:
                f.write(sublist3r_result)
        print(sublist3r_result)

        os.chdir('..')  # Go back to the original directory
# Example usage:
# passive_recon('example.com')

##############################################
############### ACTIVE RECON #################
##############################################
def active_recon(domain):
        print(f"\n{BOLD}{GREEN}[*] STARTING FINGERPRINTING{NORMAL}\n")
        print(f"{BOLD}{GREEN}[*] TARGET URL:{YELLOW} {domain} {NORMAL}\n")
        
        # Get IP address using DNS lookup
        print(f"{BOLD}{GREEN}[*] TARGET IP ADDRESS:{YELLOW} {target_ip_address} {NORMAL}\n")
        
        # Change to Pawns Directory
        os.chdir('Pawns')

        if os.path.isdir(domain):
                shutil.rmtree(domain)
        os.mkdir('Active_Recon')
        os.chdir('Active_Recon')
        
        print(f"\n{GREEN}[+] Nmap {NORMAL}\n")
        print(f"{NORMAL}{CYAN}Searching open ports...{NORMAL}\n")
        subprocess.run(f"nmap -p- --open -T5 -v -n {domain} -oN nmap.txt", shell=True)

        print(f"\n{GREEN}[+] Arp Scan {NORMAL}\n")
        print(f"{NORMAL}{CYAN}ARP Scanning beginning...{NORMAL}\n")
        subprocess.run("arp-scan -l | tee arp_scan.txt", shell=True)

        print(f"\n{GREEN}[+] DNSEnum {NORMAL}\n")
        print(f"{NORMAL}{CYAN}DNS Enumeration Running...{NORMAL}\n")
        subprocess.run(f"dnsenum {domain} | tee dnsenum.txt", shell=True)

        print(f"\n{GREEN}[+] DNSRecon {NORMAL}\n")
        print(f"{NORMAL}{CYAN}DNS Reconnaissance Initiated...{NORMAL}\n")
        subprocess.run(f"dnsrecon -d {domain} -t axfr | tee dnsrecon.txt", shell=True)
        
        print(f"\n{GREEN}[+] EyeWitness Scan {NORMAL}\n")
        print(f"{NORMAL}{CYAN}Conducting Eyewitness Scan Against Nessus Files{NORMAL}\n")
        subprocess.run("python3 eyewitness -x /opt/redsec/infra/Nessus/*.nessus", shell=True)
        
    # Change back to the original directory
        os.chdir("..")

##############################################
############### ALL MODES ####################
##############################################
def full(domain):
	passive_recon(domain)
	active_recon(domain)
	web(domain)

##############################################
############### Web Scanning ##############
##############################################
def web(domain):
        print(f"\n{BOLD}{GREEN}[*] STARTING WEB SCAN{NORMAL}\n")
        print(f"{BOLD}{GREEN}[*] TARGET URL:{YELLOW} {domain} {NORMAL}\n")

        domain_name = "https://{domain}"
        
        # Change to Pawns directory
        os.chdir('Pawns')

        # Remove existing directory if it exists
        if os.path.isdir(domain):
            os.system(f"rm -Rf {domain}")
        os.mkdir('Web_Scan')
        os.chdir('Web_Scan')

        print(f"\n{GREEN}[+] Hakrawler & gau {NORMAL}\n")
        print(f"{NORMAL}{CYAN}Gathering URLs and JavaScript file locations...{NORMAL}\n")
        with open('paths.csv', 'a') as paths_file:
            subprocess.run(['hakrawler'], input=domain.encode(), stdout=paths_file)
        subprocess.run(['gau', domain], stdout=open('paths.csv', 'a'))
        os.system("sort -u paths.csv -o paths.csv")

        print(f"\n{GREEN}[+] Arjun {NORMAL}\n")
        print(f"{NORMAL}{CYAN}Finding query parameters for URL endpoints....{NORMAL}\n")
        subprocess.run(['arjun', '-u', domain_name, '-oT', 'parameters.csv'])

        print(f"\n{GREEN}[+] DirSearch {NORMAL}\n")
        print(f"{NORMAL}{CYAN}Searching interesting directories and files...{NORMAL}\n")
        exclude_status = ""  # Define your exclude status here
        dictionary = ""  # Define your wordlist/dictionary here
        subprocess.run(['sudo', 'dirsearch', '-u', domain, '--deep-recursive', '--random-agent', '--exclude-status', exclude_status, '-w', dictionary, '-o', 'dirsearch.csv'])

        print(f"\n{GREEN}[+] Web Scan: Multiples vulnerabilities{NORMAL}\n")
        print(f"{NORMAL}{CYAN}Running multiple templates to discover vulnerabilities...{NORMAL}\n")
        subprocess.run(['nuclei', '-u', domain, '-t', '~/opt/tools/Zombz_Recon/Repositories/nuclei-templates/', '-severity', 'low,medium,high,critical', '-silent', '-o', 'mutiple_vulnerabilities.txt'])

        # Change back to the original directory
        os.chdir('..')

##############################################
############### HELP SECTION #################
##############################################
def help ():
    print(f"\n{BOLD}{GREEN}USAGE{NORMAL} [-d domain.com] [-l Target_list.txt] [-f] [-p] [-a] [-w] [-h]\n")
    print(f"{BOLD}{GREEN}TARGET OPTIONS{NORMAL} [-d domain.com] [-l Target_list.txt]\n")
    print(f"{BOLD}{GREEN}MODE OPTIONS:{NORMAL}-f, --full reconnaissance - Full scan with full target recognition and vulnerability scanning\n")
    print(f"{BOLD}{GREEN}MODE OPTIONS:{NORMAL}-p, --passive Passive reconnaissance (Footprinting) - Performs only passive recon with multiple tools\n")
    print(f"{BOLD}{GREEN}MODE OPTIONS:{NORMAL}-a, --active Active reconnaissance (Fingerprinting) - Performs only active recon with multiple tools\n")
    print(f"{BOLD}{GREEN}MODE OPTIONS:{NORMAL}-w, --web Web Scanning - Check multiple vulnerabilities in the domain/list domains\n")
    print(f"{BOLD}{GREEN}EXTRA OPTIONS:{NORMAL}-h, --help\n")
    print(f"{BOLD}{GREEN}EXAMPLES{NORMAL}{CYAN}Full reconnaissance:{NORMAL} ./Zombz_Recon.py -d domain.com -f\n")
    print(f"{CYAN}Passive reconnaissance to a list of domains:{NORMAL} ./Zombz_Recon.py -l targetList.txt -p\n")
    print(f"{CYAN}Active reconnaissance to a domain:{NORMAL} ./Zombz_Recon.py -d domain.com -a\n")
    print(f"{CYAN}Full reconnaissance and web scanning:{NORMAL} ./Zombz_Recon.py -d domain.com -f -w\n")

def usage():
    print(f"\nUsage: python Zombz_Recon.py [-t target] [-d domain] [-l target_list.txt] [-f] [-p] [-a] [-w] [-h]\n")
    sys.exit(2)

def print_banner():
    print(f"{BOLD}{GREEN}")
    os.system("figlet -f smmono9 '!! Zombz Recon !!'")
    print(f"{BOLD}{MAGENTA}They locked down their fortress - with locks!")
    print(f"\n")

def parse_arguments(args):
    domain = None
    target = None
    target_list = None
    mode_recon = 0

    if len(args) == 0:
        print(f"{RED}[!] No arguments detected \n{NORMAL}")
        sys.exit(1)

    i = 0
    while i < len(args):
        if args[i] in [ '-t', '--target']:
            target = args[i + 1]
            i += 2
        elif args[i] in ['-d', '--domain']:
            domain = args[i + 1]
            i += 2
        elif args[i] in ['-l', '--list']:
            target_list = args[i + 1]
            i += 2
        elif args[i] in ['-f', '--full']:
            mode_recon = 1
            i += 1
        elif args[i] in ['-p', '--passive']:
            mode_recon = 2
            i += 1
        elif args[i] in ['-a', '--active']:
            mode_recon = 3
            i += 1
        elif args[i] in ['-w', '--web']:
            mode_recon = 4
            i += 1
        elif args[i] in ['-h', '--help']:
            usage()
        else:
            print(f"{RED}[!] Unexpected option: {args[i]} - this should not happen. \n{NORMAL}")
            usage()

    return target, domain, target_list, mode_recon

def main(args):
    print_banner()
    target, target_list, domain, mode_recon = parse_arguments(args)

    if target is None and domain is None and target_list is None:
        print(f"{RED}[!] Please specify a target (-t), a domain (-d | --domain), or a list of targets (-l | --list) \n{NORMAL}")
        sys.exit(1)

    if not os.path.exists('Pawns'):
        os.mkdir('Pawns')

    if mode_recon == 1:
        if target_list is None and target is None:
            full(domain)
        else:
            with open(target_list, 'f') as f:
                for domain in f:
                    full(domain.strip())
    elif mode_recon == 2:
        if target_list is None and target is None:
            passive_recon(domain)
        else:
            with open(target_list, 'f') as f:
                for domain in f:
                    passive_recon(domain.strip())
    elif mode_recon == 3:
        if target_list is None and target is None:
            active_recon(domain)
        else:
            with open(target_list, 'f') as f:
                for domain in f:
                    active_recon(domain.strip())
    elif mode_recon == 4:
        if target_list is None and target is None:
            web(domain)
        else:
            with open(target_list, 'f') as f:
                for domain in f:
                    web(domain.strip())
    else:
        usage()

if __name__ == "__main__":
    main(sys.argv[1:])
