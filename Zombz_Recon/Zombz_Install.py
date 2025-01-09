#!/usr/bin/python3
import os
import subprocess

GREEN = "\033[1;32m"
MAGENTA = "\033[95m"
CYAN = "\033[36m"
BOLD = "\033[1m"
NORMAL = "\033[0m"

def print_message(color, message):
    print(f"{color}{BOLD}{message}{NORMAL}")

def install_tools():
    tools = [
        ("DNS Reconnaissance Tools", "sudo apt install -y massdns && sudo git clone https://github.com/nmmapper/dnsdumpster.git && cd dnsdumpster && sudo pip3 install -r requirements.txt && cd .."),
        ("Trufflehog - Git Repo Pilfer", "sudo apt install -y trufflehog"),
        ("Web Gathering Tools", "sudo apt install -y html2text arjun nuclei cmseek hakrawler"),
        ("Cloud Enumeration Tools", "sudo apt install -y cloud-enum s3scanner"),
        ("MailSpoof", "sudo git clone https://github.com/serain/mailspoof.git && cd mailspoof && sudo pip3 install mailspoof && cd .. && sudo apt install -y emailharvester"),
        ("Gau", "go install github.com/lc/gau/v2/cmd/gau@latest && export PATH=$PATH:$(go env GOPATH)/bin"),
        ("Screenshot Tool", "sudo apt install -y imagemagick"),
        ("Cleanup", "sudo apt-get -y autoremove")
    ]

    requirements = [ 
        "dnslib>=0.9.10", 
        "dnspython>=1.15.0", 
        "ipwhois>=1.1.0", 
        "netaddr>=0.7.19", 
        "requests", 
        "requests-html>=0.10.0", 
        "shodan>=1.13.0", 
        "selenium>=3.141.0" 
        ]
    
    print_message(GREEN, "!! Hang onto your Butts !!")
    for tool, command in tools:
        print_message(MAGENTA if "Recon" in tool or "Web" in tool or "Cloud" in tool else CYAN, f"Installing {tool}")
        subprocess.run(command, shell=True)

    print_message(CYAN, "Installing Python Requirements") 
    subprocess.run(["sudo", "pip3", "install"] + requirements)

if __name__ == "__main__":
    install_tools()
