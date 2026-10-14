![Logo of the project](https://github.com/paimmauricio/Script-Rede/blob/main/imagens/logo.png)

# 🛠 Scripts que fiz em Python para uso variado.

## 📌 Sobre este repositório

Este repositório foi criado para que eu possa colocar e compartilhar Scripts em Python que vou criando conforme vou precisando no meu dia-a-dia

## 🔹 O que os scripts fazem?

1. **IPduplicados.py** 🛡️

   - Verifica se existe IP's duplicados no range que for informado.

2. **PingAvancado.py** 📂

   - Efetua o comando PING, TRACERT, além de obter informações no ipinfo.io .

3. **Speedtest.py** 🔄

   - Verifica a velocidade de conexão.

4. **colisao.py** 🚀

   - Verifica se existe colisão na rede.
   - Obs: LOOP com o MAC que está originando é normal.
     - Caso exista colisão, irão aparecer outros MACs
    
5. **winadmin.py** 🚀
   - Ferramenta completa de administração remota Windows (via SMB/NetExec) e diagnóstico de rede local.
   - **Funcionalidades Administrador (IPs Privados/LAN):**
     - Consulta de Uptime da máquina.
     - Consulta e gerenciamento de programas instalados (Registro e WMI) com desinstalação silenciosa.
     - Gerenciamento de disco (espaço no C:) e limpeza avançada de arquivos temporários (`Temp`, `AppData\Local\Temp`, `SoftwareDistribution` e lixeira) com relatório de espaço liberado.
     - Listagem de serviços em execução e pastas compartilhadas.
     - Identificação de usuários logados no momento.
     - Reinicialização remota de máquinas.
   - **Funcionalidades de Diagnóstico (IPs Públicos e Privados):**
     - Detecção automática entre IP Público vs. Privado (pula credenciais para IPs públicos).
     - **Super Ping:** Painel interativo em tempo real com cálculo de Jitter, variação de latência e relatórios salváveis.
     - **Tracepath:** Mapeamento visual e gráfico de saltos de rota.
     - Checagem em lote de múltiplos IPs através de arquivo `.txt`.

6. **analisar_arquivos.py** 🚀
   - Automatizar a triagem estática e análise forense de arquivos suspeitos (PDF, RTF e documentos do Microsoft Office).
   - Analisa a assinatura binária física do arquivo (Magic Bytes) para identificar seu tipo real, impedindo que atacantes mascarem ameaças (como alterar a extensão de um arquivo .docm malicioso para .pdf ou .jpg). Caso encontre ameaças ativas (como macros suspeitas ou ações automáticas em PDFs), ele inicia uma dissecação profunda automatizada utilizando os utilitários pdf-parser e pdfid integrados ao sistema operacional.
     - - OBS: Nessesário instalar:
       - pdf-parser (sudo apt install pdf-parser)
       - pdfid (sudo apt install pdfid)
       - Oletools (sudo pip3 install oletools --break-system-packages)
---

### 📥 **Baixe o Script do GitHub**

1. Acesse o repositório do script no GitHub:
   - 🔗 [Scripts-Python](https://github.com/paimmauricio/Scripts-Python)
2. Clique no botão **"Code"** (Código) e selecione **"Download ZIP"**.
3. Extraia o arquivo ZIP para uma pasta de fácil acesso, como a Área de Trabalho.

---

## ⚠️ Importante
- **Execute antes em uma máquina virtual**
- **Crie um ponto de restauração**
- **Se algo não funcionar como esperado, use a opção de restauração** para voltar ao estado anterior.
- **Este script foi testado em versões recentes do Windows**, mas recomenda-se criar um backup completo do sistema antes de utilizá-lo.

---

## ❤️ Apoie este projeto

Se este script foi útil para você e deseja apoiar o projeto, considere fazer uma doação:

### 💳 Via transferência Unibanco
- **Agência:** 8488  
- **C/C:** 0047854-9

### 🏦 Via Pix  
📌 Chave Pix: paim.mauricio@gmail.com

### 💰 Via QR Code PayPal
[![QR Code PayPal](https://github.com/paimmauricio/Script-Rede/blob/main/QRs/QR_Code_PayPal.png)](https://github.com/paimmauricio/Script-Rede/blob/main/QRs/QR_Code_PayPal.png)

### 🌍 Via Site PayPal
[Doação Direta pelo PayPal](https://www.paypal.com/donate?hosted_button_id=YJNX67EAAHNCU)

---

## 👨‍💻 Autor

- **Maurício Paim**  
  - 🔗 [GitHub](https://github.com/paimmauricio) *(Clique para acessar o repositório!)*

---

## 🎉 Divirta-se!

Obrigado pela visita! 😊

