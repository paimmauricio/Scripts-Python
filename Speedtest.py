import speedtest
import socket
import requests
import warnings

# Oculta o aviso de requisição HTTPS não verificada
warnings.simplefilter("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

def obter_informacoes_rede():
    try:
        # Obtendo IP público e provedor (desativando verificação SSL)
        ip_info = requests.get("https://ipinfo.io/json", verify=False).json()
        
        ip_publico = ip_info.get("ip", "Desconhecido")
        isp = ip_info.get("org", "Desconhecido")
        cidade = ip_info.get("city", "Desconhecido")
        regiao = ip_info.get("region", "Desconhecido")
        pais = ip_info.get("country", "Desconhecido")

        # Obtendo o IP local e nome do computador
        nome_pc = socket.gethostname()
        ip_local = socket.gethostbyname(nome_pc)

        print(f"Nome do Computador: {nome_pc}")
        print(f"IP Local: {ip_local}")
        print(f"IP Público: {ip_publico}")
        print(f"Provedor: {isp}")
        print(f"Localização: {cidade}, {regiao}, {pais}\n")
    except Exception as e:
        print(f"Erro ao obter informações de IP: {e}")

def testar_velocidade():
    try:
        st = speedtest.Speedtest()
        st.get_best_server()

        print("Testando download...")
        velocidade_download = st.download() / 1_000_000  # Convertendo para Mbps

        print("Testando upload...")
        velocidade_upload = st.upload() / 1_000_000  # Convertendo para Mbps

        ping = st.results.ping
        servidor = st.results.server

        print("\n=== Resultados do Teste de Velocidade ===")
        print(f"Download: {velocidade_download:.2f} Mbps")
        print(f"Upload: {velocidade_upload:.2f} Mbps")
        print(f"Latência (Ping): {ping:.2f} ms")
        print(f"Servidor: {servidor['sponsor']} - {servidor['name']} ({servidor['country']})")
        print(f"Host: {servidor['host']}")

    except Exception as e:
        print(f"Erro ao testar a velocidade: {e}")

if __name__ == "__main__":
    print("=== Informações da Rede ===")
    obter_informacoes_rede()
    print("\n=== Teste de Velocidade ===")
    testar_velocidade()
