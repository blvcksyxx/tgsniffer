import os
import sys
import ipaddress
import threading
import time
import requests
import keyboard
from scapy.all import sniff, UDP, IP, conf
from rich.console import Console
from rich.panel import Panel
from rich.live import Live
from rich.table import Table

if os.name == 'nt':
    import winsound

console = Console()

black_subnets = [
    ipaddress.ip_network("91.105.192.0/23"), ipaddress.ip_network("91.108.4.0/22"),
    ipaddress.ip_network("91.108.8.0/22"), ipaddress.ip_network("91.108.12.0/22"),
    ipaddress.ip_network("91.108.16.0/22"), ipaddress.ip_network("91.108.20.0/22"),
    ipaddress.ip_network("91.108.56.0/23"), ipaddress.ip_network("91.108.58.0/23"),
    ipaddress.ip_network("95.161.64.0/20"), ipaddress.ip_network("149.154.160.0/21"),
    ipaddress.ip_network("149.154.168.0/22"), ipaddress.ip_network("149.154.172.0/22"),
    ipaddress.ip_network("185.76.151.0/24")
]

drop_isp_keywords = ["google", "cloudflare", "amazon", "microsoft", "digitalocean", "hetzner", "ovh"]

ip_traffic = {}
active_filter = ""
is_running = True
geoip_cache = {}
alerted_ips = set()
target_iface = None

def get_geoip_info(ip_str):
    """async geoip lookup loop fetching country, city, and isp"""
    if ip_str in geoip_cache:
        return geoip_cache[ip_str]
    
    geoip_cache[ip_str] = {"location": "unknown", "org": "searching..."}
    
    def fetch():
        try:
            res = requests.get(f"http://ip-api.com/json/{ip_str}?fields=country,city,org", timeout=2).json()
            country = res.get("country", "unknown").lower()
            city = res.get("city", "unknown").lower()
            
            geoip_cache[ip_str] = {
                "location": f"{country}, {city}" if city != "unknown" else country,
                "org": res.get("org", "unknown").lower()
            }
        except:
            geoip_cache[ip_str] = {"location": "error", "org": "error"}
            
    threading.Thread(target=fetch, daemon=True).start()

def is_tg_subnet(ip_str):
    """validate if destination ip lies inside tg ranges"""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return any(ip_obj in subnet for subnet in black_subnets)
    except ValueError:
        return False

def process_packet(packet):
    """intercept and process raw network streams"""
    global is_running
    if not is_running:
        return
    if packet.haslayer(UDP) and packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_len = len(packet)

        if 100 <= packet_len <= 1300:
            remote_ip = src_ip if not src_ip.startswith("192.168.") and not src_ip.startswith("127.") and not src_ip.startswith("10.") else dst_ip
            
            if remote_ip.startswith("192.168.") or remote_ip.startswith("127.") or remote_ip.startswith("10.") or remote_ip.startswith("224.") or remote_ip.startswith("239.") or remote_ip.startswith("0.") or remote_ip.startswith("255."):
                return

            if is_tg_subnet(remote_ip):
                pass
            else:
                if remote_ip in geoip_cache:
                    isp_name = geoip_cache[remote_ip]["org"].lower()
                    if any(kw in isp_name for kw in drop_isp_keywords):
                        return

            if remote_ip not in ip_traffic:
                ip_traffic[remote_ip] = {"packets": 0, "bytes": 0}
                get_geoip_info(remote_ip)
            
            ip_traffic[remote_ip]["packets"] += 1
            ip_traffic[remote_ip]["bytes"] += packet_len

def generate_ui():
    """compile localized bento grid output layer"""
    flt_status = f"[bold green]{active_filter}[/]" if active_filter else "[dim]none[/]"
    
    # safe interface name extraction handling both string and object formats
    if target_iface:
        iface_name = target_iface if isinstance(target_iface, str) else getattr(target_iface, "name", "unknown")
    else:
        iface_name = "default"
        
    table = Table(
        title=f"monitoring traffic | interface: {iface_name.lower()} | filter: {flt_status}", 
        title_style="bold magenta", 
        expand=True
    )
    table.add_column("target ip", style="cyan", no_wrap=True)
    table.add_column("location", style="purple")
    table.add_column("isp", style="blue")
    table.add_column("packets", style="yellow", justify="right")
    table.add_column("data", style="green", justify="right")
    table.add_column("status", justify="center")

    sorted_traffic = sorted(ip_traffic.items(), key=lambda x: x[1]["packets"], reverse=True)

    for ip, stats in sorted_traffic:
        geo = geoip_cache.get(ip, {"location": "loading...", "org": "loading..."})
        location = geo["location"]
        isp = geo["org"]

        if any(kw in isp.lower() for kw in drop_isp_keywords):
            continue

        if active_filter:
            search_zone = f"{ip} {location} {isp}".lower()
            if active_filter.lower() not in search_zone:
                continue

        if "telegram" in isp.lower() or is_tg_subnet(ip):
            display_ip = f"[s]{ip}[/]"
            display_loc = f"[s]{location}[/]"
            display_isp = f"[s]{isp}[/]"
            status = "[dim]tg server[/]"
        else:
            display_ip = ip
            display_loc = location
            display_isp = isp
            
            if stats["packets"] > 40:
                status = "[bold pulse red]spotted[/]"
                if ip not in alerted_ips and os.name == 'nt':
                    alerted_ips.add(ip)
                    threading.Thread(target=lambda: winsound.Beep(600, 250), daemon=True).start()
            else:
                status = "[dim]scanning...[/]"

        kb = round(stats["bytes"] / 1024, 1)
        table.add_row(display_ip, display_loc, display_isp, str(stats["packets"]), f"{kb} kb", status)
        
    footer = r"[bold magenta]\[f][/] filter | [bold magenta]\[r][/] reset | [bold magenta]\[c][/] clear | [bold magenta]\[q][/] quit"
    return Panel(table, border_style="bright_blue", title="[bold green]@blvcksyxx tg sniffer [v3][/]", subtitle=footer)

def start_sniffing():
    """scapy network socket polling thread bound to selected interface"""
    sniff(iface=target_iface, filter="udp", prn=process_packet, store=0, stop_filter=lambda p: not is_running)

def main():
    global active_filter, ip_traffic, is_running, target_iface
    
    if os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
        console.print("[bold red][-] error: run application as administrator![/]")
        return

    # wipe out initial terminal log garbage before setup
    os.system('cls' if os.name == 'nt' else 'clear')

    try:
        target_iface = conf.route.route("8.8.8.8")[0]
    except:
        target_iface = None

    threading.Thread(target=start_sniffing, daemon=True).start()
    console.print("[bold green][+] backend stack initialized successfully.[/]")
    console.print("[bold green][+] sub to @blvcksyxx on telegram for more cool projects![/]")

    with Live(generate_ui(), refresh_per_second=4) as live:
        while is_running:
            live.update(generate_ui())
            time.sleep(0.25)
            
            if keyboard.is_pressed('f'):
                live.stop()
                console.print("\n" + "─" * 50)
                new_filter = console.input("[bold yellow][?] enter manual search query: [/]")
                active_filter = new_filter.strip().lower()
                console.print("─" * 50 + "\n")
                os.system('cls' if os.name == 'nt' else 'clear')
                live.start()
                
            elif keyboard.is_pressed('r'):
                ip_traffic.clear()
                alerted_ips.clear()
                
            elif keyboard.is_pressed('c'):
                active_filter = ""
                os.system('cls' if os.name == 'nt' else 'clear')
                
            elif keyboard.is_pressed('q'):
                is_running = False
                live.stop()
                console.print("[bold red][!] shutting down network interface sockets...[/]")
                sys.exit(0)

if __name__ == "__main__":
    import ctypes
    main()
