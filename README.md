![Logo of the project](https://github.com/paimmauricio/Script-Rede/blob/main/imagens/logo.png)

# 🛠 Windows Tweak & Backup Script

## 📌 Sobre este script

Este script foi desenvolvido para otimizar e ajustar configurações do Windows, garantindo um melhor desempenho e experiência do usuário. Além disso, ele inclui um sistema de **backup e restauração**, permitindo que qualquer alteração feita possa ser revertida facilmente caso necessário.

## 🔹 O que este script faz?

1. **Verifica se está sendo executado como administrador** 🛡️

   - Algumas configurações do sistema exigem privilégios administrativos. Se o script for iniciado sem esses privilégios, ele exibirá um aviso e será encerrado.

2. **Cria um backup das configurações atuais** 📂

   - Antes de aplicar qualquer alteração, o script salva as configurações originais do sistema para garantir que possam ser restauradas se algo não funcionar como esperado.

3. **Permite restaurar as configurações originais** 🔄

   - O usuário pode optar por restaurar um backup anterior caso queira reverter as alterações feitas pelo script.

4. **Aplica otimizações no Windows** 🚀

   - O script realiza ajustes para melhorar o desempenho e a usabilidade do sistema operacional.

5. **Exibe mensagens informativas** 🖥️

   - Durante toda a execução, o usuário recebe notificações sobre o que está acontecendo, tornando o processo mais transparente e intuitivo.

---

## 🔧 **# Como Usar o Script**

### 📥 **1. Baixe o Script do GitHub**

1. Acesse o repositório do script no GitHub:
   - 🔗 [WindowsTweak](https://github.com/paimmauricio/WindowsTweak)
2. Clique no botão **"Code"** (Código) e selecione **"Download ZIP"**.
3. Extraia o arquivo ZIP para uma pasta de fácil acesso, como a Área de Trabalho.
4. Alternativamente, você pode baixar o script diretamente usando o PowerShell:
   ```powershell
   Invoke-WebRequest -Uri "https://github.com/paimmauricio/WindowsTweak/blob/main/WindowsTweak.ps1" -OutFile "WindowsTweak.ps1"  
   ```

### 🔍 **2. Execute como Administrador**

- Clique com o **botão direito** no arquivo **WindowsTweak.ps1** e selecione **"Executar com o PowerShell"**.
- Ou abra o PowerShell na pasta onde baixou o script e execute:
  ```powershell
  Set-ExecutionPolicy Unrestricted -Scope Process  
  .\WindowsTweak.ps1  
  ```
  - Se for solicitado, confirme pressionando **"S"** e **Enter**.

### 🔄 **3. Escolha Restaurar ou Aplicar Otimizações**

- O script perguntará se deseja **restaurar um backup anterior** ou **aplicar as otimizações no sistema**.
  - **Para restaurar um backup**: Digite **S** e pressione **Enter**.
  - **Para aplicar as otimizações**: Digite **N** e pressione **Enter**.

### ⏳ **4. Aguarde a Conclusão**

- O script criará um backup antes de modificar as configurações do Windows.
- Em seguida, aplicará as otimizações automaticamente.

### 🔄 **5. Reinicie o Computador**

- Após a conclusão, **reinicie o computador** para que todas as mudanças tenham efeito.

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

## 📌 Versão

- **1.0**

## 👨‍💻 Autor

- **Maurício Paim**  
  - 🔗 [GitHub](https://github.com/paimmauricio) *(Clique para acessar o repositório!)*

---

## 🎉 Divirta-se!

Obrigado pela visita! 😊

