from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.http import HTTPRequest
from colorama import init, Fore

init()

red = Fore.RED
green = Fore.GREEN
blue = Fore.BLUE
reset = Fore.RESET

def sniff_packets(iface):
    if iface:
        sniff(filter="tcp port 80", prn=process_packet, iface=iface, store=False)
    else:
        sniff(prn=process_packet, store=False)

def process_packet(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        print(f"{blue}[+] {src_ip} is using port {src_port} to connect to {dst_ip} at port {dst_port}{reset}")

    if packet.haslayer(HTTPRequest):
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        method = packet[HTTPRequest].Method.decode()
        print(f"{green}[+] {src_ip} is making an HTTP request to {url} with method {method}{reset}")

        # Extract headers from the HTTPRequest layer
        print(f"{red}[+] HTTP Headers:{reset}")
        headers = {field: packet[HTTPRequest].getfieldval(field) for field in packet[HTTPRequest].fields}
        for key, value in headers.items():
            if value:
                print(f"{red}{key}: {value}{reset}")

        # Extract Raw payload if available
        if packet.haslayer(Raw):
            try:
                raw_data = packet[Raw].load.decode(errors="ignore")
                print(f"{red}[+] HTTP Raw Data:{reset}\n{raw_data}")
            except Exception as e:
                print(f"{red}[!] Error decoding Raw data: {e}{reset}")

sniff_packets("Wi-Fi")
