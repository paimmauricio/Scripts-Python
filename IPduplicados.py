from scapy.all import ARP, Ether, srp
import ipaddress

def check_ip_conflict(ip_range):
    conflicts = {}
    
    # Gera a lista de IPs a partir do input
    ip_list = []
    if '-' in ip_range:
        start_ip, end_ip = ip_range.split('-')
        start_ip = ipaddress.IPv4Address(start_ip)
        end_ip = ipaddress.IPv4Address(end_ip)
        
        for ip_int in range(int(start_ip), int(end_ip) + 1):
            ip_list.append(str(ipaddress.IPv4Address(ip_int)))
    else:
        ip_list.append(ip_range)
    
    # Monta e envia os pacotes ARP
    for ip in ip_list:
        arp_request = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp_request
        
        result = srp(packet, timeout=2, verbose=False)[0]
        mac_addresses = set()
        
        for sent, received in result:
            mac_addresses.add(received.hwsrc)
        
        if len(mac_addresses) > 1:
            conflicts[ip] = list(mac_addresses)
    
    # Exibe os conflitos encontrados
    if conflicts:
        print("Conflitos de IP detectados:")
        for ip, macs in conflicts.items():
            print(f"IP {ip} está sendo usado por múltiplos MACs: {', '.join(macs)}")
    else:
        print("Nenhum conflito detectado.")

# Exemplo de uso
if __name__ == "__main__":
    ip_range = input("Digite um IP ou intervalo (ex: 192.168.1.1 ou 192.168.1.1-192.168.1.10): ")
    check_ip_conflict(ip_range)
