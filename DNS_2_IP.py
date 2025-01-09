import socket

# Function to resolve DNS name and get IP address
def resolve_dns(url):
    try:
        ip = socket.gethostbyname(url)
        return ip
    except socket.gaierror:
        return None

# Read URLs from infile.csv
with open('infile.csv', 'r') as infile:
    urls = infile.readlines()

# Open outfile.txt for writing
with open('outfile.txt', 'w') as outfile:
    for url in urls:
        url = url.strip()
        ip = resolve_dns(url)
        if ip:
            outfile.write(f"{url},{ip}\n")
        else:
            outfile.write(f"{url},Error: Couldn't get IP\n")
