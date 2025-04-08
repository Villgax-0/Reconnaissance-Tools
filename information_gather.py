import sys
import whois
import dns.resolver
import shodan
import requests
import argparse
import socket

# Argument Parser
argparse = argparse.ArgumentParser(description="Information Gathering Tool", usage="python info_gathering.py -d DOMAIN [-s IP]")
argparse.add_argument("-d", "--domain", help="Enter the Domain for Footprinting.", required=True)
argparse.add_argument("-s", "--shodan", help="Enter the IP for Shodan search.")
argparse.add_argument("-o","--output",help="Enter the file to write output to.")

args = argparse.parse_args( )
domain = args.domain
ip = args.shodan
output = args.output

print("[+] Domain: {} | IP: {}".format(domain, ip))

# WHOIS Lookup
whois_result = ''
try:
    py = whois.whois(domain)
    print("[+] WHOIS info found.")
    print("Name: {}".format(py.name))
    print("Registrar: {}".format(py.registrar))
    print("Creation Date: {}".format(py.creation_date))
    print("Expiration Date: {}".format(py.expiration_date))
    print("Registrant Country: {}".format(py.registrant_country))
except Exception as e:
    print("[-] WHOIS lookup failed:", e)

# DNS Lookup
print("[+] Getting DNS Info...")
try:

    for a in dns.resolver.resolve(domain, 'A'):
        print("[+] A Record: {}".format(a.to_text()))
    for ns in dns.resolver.resolve(domain, 'NS'):
        print("[+] NS Record: {}".format(ns.to_text()))
    for mx in dns.resolver.resolve(domain, 'MX'):
        print("[+] MX Record: {}".format(mx.to_text()))
    for txt in dns.resolver.resolve(domain, 'TXT'):
        print("[+] TXT Record: {}".format(txt.to_text()))
except Exception as e:
    print("[-] DNS lookup failed:", e)

# Geolocation Lookup
print("[+] Getting geolocation info...")
try:
    ip_address = socket.gethostbyname(domain)
    response = requests.get(f"https://geolocation-db.com/json/{ip_address}&position=true").json()
    print("[+] Country: {}".format(response.get('country_name', 'N/A')))
    print("[+] Latitude: {}".format(response.get('latitude', 'N/A')))
    print("[+] Longitude: {}".format(response.get('longitude', 'N/A')))
    print("[+] City: {}".format(response.get('city', 'N/A')))
    print("[+] State: {}".format(response.get('state', 'N/A')))
except Exception as e:
    print("[-] Geolocation lookup failed:", e)

# Shodan Lookup
if ip:
    print("[+] Getting info from Shodan for IP {}".format(ip))
    api = shodan.Shodan("API-KEY")  # Replace with actual API key of Shodan.
    try:
        results = api.host(ip)
        print("[+] IP: {}".format(results['ip_str']))
        print("[+] Organization: {}".format(results.get('org', 'N/A')))
        print("[+] ISP: {}".format(results.get('isp', 'N/A')))
        print("[+] Country: {}".format(results.get('country_name', 'N/A')))
        for item in results['data']:
            print("[+] Port: {}".format(item['port']))
            print("[+] Banner: {}".format(item.get('data', 'N/A')))
    except shodan.APIError as e:
        print(f"[-] Shodan search error: {e}")
