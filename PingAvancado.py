import os
import socket
import requests
import subprocess
import urllib3
from ipwhois import IPWhois

# Desabilita os avisos de SSL (InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Função para obter informações sobre o IP
def obter_informacoes_ip(ip):
    try:
        ip_info = requests.get(f"https://ipinfo.io/{ip}/json", verify=True).json()
        hostname = ip_info.get("hostname", "Desconhecido")
        org = ip_info.get("org", "Desconhecido")
        cidade = ip_info.get("city", "Desconhecido")
        regiao = ip_info.get("region", "Desconhecido")
        pais = ip_info.get("country", "Desconhecido")
        coordenadas = ip_info.get("loc", "Desconhecido").split(",")

        # Usando IPWhois para obter ASN e outros dados de rede
        ipwhois = IPWhois(ip)
        resultado_ipwhois = ipwhois.lookup_rdap()
        asn = resultado_ipwhois.get('asn', 'Desconhecido')
        
        print(f"\n=== Informações do IP ===")
        print(f"IP: {ip}")
        print(f"Hostname: {hostname}")
        print(f"Provedor: {org}")
        print(f"Localização: {cidade}, {regiao}, {pais}")
        print(f"Coordenadas: {coordenadas[0]}, {coordenadas[1]}")
        print(f"ASN: {asn}")
    except Exception as e:
        print(f"Erro ao obter informações de IP: {e}")

# Função para realizar o ping e verificar a latência
def realizar_ping(ip):
    print("\n=== Teste de Ping ===")
    resposta = []
    for i in range(4):
        response = os.popen(f"ping -n 1 {ip}").read()
        if "Resposta" in response:
            resposta.append("Sucesso")
        else:
            resposta.append("Falhou")
    print(f"Respostas do ping: {resposta}")

# Função para realizar o traceroute
def realizar_traceroute(ip):
    print("\n=== Traceroute Avançado ===")
    try:
        traceroute_result = subprocess.check_output(["tracert", ip], stderr=subprocess.STDOUT, text=True)
        linhas = traceroute_result.splitlines()
        for linha in linhas[4:]:  # Começa a partir do 5º salto
            partes = linha.split()
            if len(partes) >= 3:
                hop = partes[0]
                ip_salto = partes[1].strip('[]')
                print(f"Hop: {hop} | IP: {ip_salto}")
                obter_informacoes_ip(ip_salto)  # Informações de cada IP no traceroute
    except Exception as e:
        print(f"Erro no traceroute: {e}")

# Função principal
def analisar_ip(fqdn):
    print(f"\n🔍 Analisando: {fqdn}")
    
    # Resolvendo o IP
    try:
        ip = socket.gethostbyname(fqdn)
        print(f"IP Resolvido: {ip}")
        
        # Obtendo informações sobre o IP
        obter_informacoes_ip(ip)
        
        # Realizando o ping
        realizar_ping(ip)
        
        # Realizando o traceroute
        realizar_traceroute(ip)
        
    except Exception as e:
        print(f"Erro ao resolver o FQDN: {e}")

# Entrada de dados
if __name__ == "__main__":
    fqdn = input("Digite um IP ou FQDN para análise: ").strip()
    analisar_ip(fqdn)
