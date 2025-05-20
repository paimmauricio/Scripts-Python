from scapy.all import sniff, ARP, Ether
from collections import defaultdict
import time

# Configurações
LOOP_THRESHOLD = 10  # Número de pacotes idênticos em menos de 1 segundo
BROADCAST_THRESHOLD = 50  # Limite de broadcasts por segundo

# Variáveis para monitoramento
packet_cache = defaultdict(list)
broadcast_count = 0
start_time = time.time()

def packet_handler(packet):
    global broadcast_count, start_time
    current_time = time.time()
    
    # Reseta contagem de broadcast a cada segundo
    if current_time - start_time >= 1:
        start_time = current_time
        broadcast_count = 0
    
    # Identifica broadcast storms
    if packet.haslayer(Ether) and packet[Ether].dst == "ff:ff:ff:ff:ff:ff":
        broadcast_count += 1
        if broadcast_count > BROADCAST_THRESHOLD:
            print("⚠️ Alerta: Tempestade de broadcast detectada!")
    
    # Verifica pacotes duplicados (indício de loop)
    pkt_id = (packet.src, packet.dst, packet.type)
    timestamps = packet_cache[pkt_id]
    timestamps.append(current_time)
    
    # Mantém apenas os pacotes recentes
    timestamps = [t for t in timestamps if current_time - t < 1]
    packet_cache[pkt_id] = timestamps
    
    if len(timestamps) > LOOP_THRESHOLD:
        print(f"⚠️ Alerta: Possível loop detectado para tráfego entre {packet.src} e {packet.dst}")
    
# Captura pacotes na interface de rede
print("Monitorando a rede... Pressione Ctrl+C para interromper.")
sniff(prn=packet_handler, store=False)
