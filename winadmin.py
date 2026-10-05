#!/usr/bin/env python3

import subprocess
import re
from datetime import datetime, timezone, timedelta
import getpass
import sys
import os
import base64
import platform
import time
import threading
import queue
import select
import tty
import termios
import ipaddress
from collections import deque

# ==========================================
# Verificação e Inicialização da Biblioteca Rich
# ==========================================
try:
    from rich.console import Console
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.layout import Layout
    from rich.text import Text
    from rich import box
except ImportError:
    print("[!] Erro: A biblioteca 'rich' não está instalada.")
    print("No seu sistema, instale usando: sudo apt install python3-rich -y ou pip install rich")
    sys.exit(1)

console = Console()

MAX_LINHAS = 12
LIMIAR_OTIMO = 50
LIMIAR_MEDIANO = 150

def clear_screen():
    os.system('clear' if platform.system() != 'Windows' else 'cls')

def getch_char_non_blocking():
    """Lê um único caractere do terminal sem bloquear a execução."""
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        if select.select([sys.stdin], [], [], 0) == ([sys.stdin], [], []):
            return sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return None

def ler_saida_subprocesso(processo, fila):
    """Lê linha a linha em tempo real sem buffering."""
    for linha in iter(processo.stdout.readline, ""):
        fila.put(linha)
    processo.stdout.close()

def eh_ip_privado(host):
    """Verifica se o IP informado é um IP privado (Rede Interna/LAN)."""
    try:
        ip_obj = ipaddress.ip_address(host)
        return ip_obj.is_private
    except ValueError:
        return True

# ==========================================
# MÓDULO: NetExec & Administração Remota
# ==========================================
def run_nxc_command(cmd, silent_error=False):
    """Executa o NetExec e captura a saída."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        if not silent_error:
            console.print(Panel(f"[bold red]Erro ao executar comando no alvo:[/bold red]\n{e.stderr or e.stdout}", title="Erro NXC", border_style="red"))
        return None
    except FileNotFoundError:
        console.print("[bold red][!] Erro: NetExec (nxc) não encontrado no PATH.[/bold red]")
        sys.exit(1)

def checar_credenciais(user):
    """Verifica se as credenciais foram fornecidas antes de rodar comandos de admin."""
    if not user:
        console.print("[bold red][!] Esta função exige acesso administrativo à rede interna (Credenciais necessárias).[/bold red]")
        return False
    return True

def get_free_space_bytes(ip, user, password, domain):
    """Consulta rápida do espaço livre na unidade C: em bytes via WMI."""
    cmd = ["nxc", "smb", ip, "-u", user, "-p", password, "-d", domain, "--wmi-query", "Select FreeSpace from Win32_LogicalDisk Where DeviceID='C:'"]
    output = run_nxc_command(cmd, silent_error=True)
    if output:
        match = re.search(r'FreeSpace\s*(?:=>|:)\s*(\d+)', output, re.IGNORECASE)
        if match:
            return int(match.group(1))
    return None

def check_uptime(ip, user, password, domain):
    if not checar_credenciais(user): return
    console.print(f"\n[bold blue][*] Consultando Uptime em {ip}...[/bold blue]")
    cmd = ["nxc", "smb", ip, "-u", user, "-p", password, "-d", domain, "--wmi-query", "Select LastBootUpTime from Win32_OperatingSystem"]
    output = run_nxc_command(cmd)
    if not output: return

    match = re.search(r"LastBootUpTime\s*(?:=>|:)\s*(\d{14})\.\d+([+-]\d{3})", output)
    if match:
        time_str = match.group(1)
        offset_mins = int(match.group(2))
        tz_win = timezone(timedelta(minutes=offset_mins))
        dt_boot = datetime.strptime(time_str, "%Y%m%d%H%M%S").replace(tzinfo=tz_win)
        now_utc = datetime.now(timezone.utc)
        uptime = now_utc - dt_boot
        d = uptime.days
        h, rem = divmod(uptime.seconds, 3600)
        m, _ = divmod(rem, 60)
        boot_local = dt_boot.astimezone().strftime("%d/%m/%Y às %H:%M:%S")

        table = Table(title="Informações de Uptime", border_style="green", box=box.ROUNDED)
        table.add_column("Métrica", style="bold cyan")
        table.add_column("Valor", style="bold white")
        table.add_row("Tempo Ativo", f"{d} dias, {h} horas e {m} minutos")
        table.add_row("Ligado em", boot_local)
        console.print(table)
    else:
        console.print("[yellow][-] Não foi possível encontrar a data de reinicialização.[/yellow]")

def search_program_registry(ip, user, password, domain):
    if not checar_credenciais(user): return
    console.print("\n[dim yellow]Dica: Deixe em branco e pressione ENTER para listar TODOS os programas.[/dim yellow]")
    termo = console.input("[cyan]Digite parte do nome do programa para pesquisar: [/cyan]").strip()
    console.print("[bold blue][*] Consultando o Registro do Windows via PowerShell...[/bold blue]")

    filtro = f" | Where-Object {{$_.DisplayName -match '{termo}'}}" if termo else ""
    ps_cmd = f"Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue | Where-Object DisplayName{filtro} | Sort-Object DisplayName | ForEach-Object {{ Write-Output ('[APP]' + $_.DisplayName + ' | v' + $_.DisplayVersion) }}"
    cmd = ["nxc", "smb", ip, "-u", user, "-p", password, "-d", domain, "-x", f'powershell -NoProfile -Command "{ps_cmd}"']

    output = run_nxc_command(cmd)
    if not output: return

    table = Table(title="Programas Encontrados (Registro)", border_style="green", box=box.ROUNDED, expand=True)
    table.add_column("Nome do Programa", style="bold white")
    table.add_column("Versão", style="cyan", justify="right")

    encontrou = False
    for line in output.splitlines():
        if "[APP]" in line:
            clean_line = line.split("[APP]")[1].strip()
            parts = clean_line.split(" | v")
            nome = parts[0]
            versao = parts[1] if len(parts) > 1 else "N/A"
            table.add_row(nome, versao)
            encontrou = True

    if encontrou:
        console.print(table)
    else:
        console.print("[yellow]Nenhum programa correspondente foi encontrado.[/yellow]")

def search_program_wmi(ip, user, password, domain):
    if not checar_credenciais(user): return
    console.print("\n[dim yellow]Dica: Deixe em branco e pressione ENTER para listar TODOS os programas MSI.[/dim yellow]")
    termo = console.input("[cyan]Digite parte do nome do programa para pesquisar: [/cyan]").strip()
    console.print("[bold blue][*] Consultando registro WMI (Pode demorar um pouco)...[/bold blue]")

    query = f"Select Name, Version from Win32_Product Where Name Like '%{termo}%'" if termo else "Select Name, Version from Win32_Product"
    cmd = ["nxc", "smb", ip, "-u", user, "-p", password, "-d", domain, "--wmi-query", query]

    output = run_nxc_command(cmd)
    if not output: return

    table = Table(title="Programas Encontrados (WMI)", border_style="green", box=box.ROUNDED, expand=True)
    table.add_column("Saída WMI", style="bold white")

    encontrou = False
    for line in output.splitlines():
        if "Name" in line and "Version" in line:
            clean_line = re.sub(r'^SMB\s+[\d\.]+\s+\d+\s+[A-Za-z0-9_-]+\s+', '', line).strip()
            table.add_row(clean_line)
            encontrou = True

    if encontrou:
        console.print(table)
    else:
        console.print("[yellow]Nenhum pacote MSI correspondente foi encontrado.[/yellow]")

def uninstall_program(ip, user, password, domain):
    if not checar_credenciais(user): return
    nome_exato = console.input("\n[cyan]Nome exato do programa a desinstalar (vazio para cancelar): [/cyan]").strip()
    if not nome_exato: return
    console.print(f"[bold blue][*] Enviando comando de desinstalação silenciosa para '{nome_exato}'...[/bold blue]")
    cmd = ["nxc", "smb", ip, "-u", user, "-p", password, "-d", domain, "-x", f'wmic product where name="{nome_exato}" call uninstall /nointeractive']
    output = run_nxc_command(cmd)
    if not output: return

    if "ReturnValue = 0" in output or "Method execution successful" in output:
        console.print(f"[bold green][+] Sucesso! O programa '{nome_exato}' foi desinstalado.[/bold green]\n")
    elif "No Instance(s) Available" in output:
        console.print(f"[bold red][!] Programa não encontrado pelo WMI.[/bold red]\n")
    else:
        console.print(Panel(output, title="Resposta do Servidor", border_style="yellow"))

def menu_programas(ip, user, password, domain):
    """Submenu de gerenciamento de programas."""
    if not checar_credenciais(user): return
    while True:
        clear_screen()
        console.print(Panel(f"[bold cyan]GERENCIAR PROGRAMAS INSTALADOS ({ip})[/bold cyan]", border_style="blue"))
        console.print("[yellow]1.[/yellow] Pesquisar Programas (Registro - Rápido)")
        console.print("[yellow]2.[/yellow] Pesquisar Programas (WMI - Lento)")
        console.print("[yellow]3.[/yellow] Desinstalar Programa (WMI)")
        console.print("[red]0.[/red] Voltar ao Menu Principal\n")

        opcao = console.input("[bold]Escolha uma opção: [/bold]").strip()

        if opcao == '1': search_program_registry(ip, user, password, domain)
        elif opcao == '2': search_program_wmi(ip, user, password, domain)
        elif opcao == '3': uninstall_program(ip, user, password, domain)
        elif opcao == '0': break
        else: console.print("[red]Opção inválida![/red]")

        if opcao != '0': console.input("\n[dim yellow]Pressione ENTER para continuar...[/dim yellow]")

def check_disk_space(ip, user, password, domain):
    if not checar_credenciais(user): return
    console.print(f"\n[bold blue][*] Consultando armazenamento da unidade C:...[/bold blue]")
    cmd = ["nxc", "smb", ip, "-u", user, "-p", password, "-d", domain, "--wmi-query", "Select DeviceID, FreeSpace, Size from Win32_LogicalDisk Where DeviceID='C:'"]
    output = run_nxc_command(cmd)

    if output:
        free_bytes = None
        size_bytes = None

        for line in output.splitlines():
            free_match = re.search(r'FreeSpace\s*(?:=>|:)\s*(\d+)', line, re.IGNORECASE)
            size_match = re.search(r'Size\s*(?:=>|:)\s*(\d+)', line, re.IGNORECASE)

            if free_match: free_bytes = int(free_match.group(1))
            if size_match: size_bytes = int(size_match.group(1))

        if free_bytes is not None and size_bytes is not None and size_bytes > 0:
            size_gb = size_bytes / (1024**3)
            free_gb = free_bytes / (1024**3)
            used_gb = size_gb - free_gb

            size_mb = size_bytes / (1024**2)
            free_mb = free_bytes / (1024**2)
            used_mb = size_mb - free_mb

            percent_used = (used_gb / size_gb) * 100
            cor_uso = "bold red" if percent_used > 85 else "bold green"

            table = Table(title="Armazenamento da Unidade C:", border_style="bright_blue", box=box.ROUNDED)
            table.add_column("Métrica", style="bold white")
            table.add_column("Gigabytes (GB)", justify="right")
            table.add_column("Megabytes (MB)", justify="right")
            table.add_column("Percentual", justify="center")

            table.add_row("Tamanho Total", f"{size_gb:.2f} GB", f"{size_mb:,.0f} MB", "100%")
            table.add_row("Espaço Usado", f"[{cor_uso}]{used_gb:.2f} GB[/]", f"[{cor_uso}]{used_mb:,.0f} MB[/]", f"[{cor_uso}]{percent_used:.1f}%[/]")
            table.add_row("Espaço Livre", f"[green]{free_gb:.2f} GB[/green]", f"[green]{free_mb:,.0f} MB[/green]", f"{100 - percent_used:.1f}%")

            console.print(table)
            return

    console.print("[yellow]Não foi possível obter informações da unidade C:.[/yellow]")

def clean_temp_files(ip, user, password, domain):
    if not checar_credenciais(user): return
    console.print(Panel(
        "[bold red]ROTINA DE LIMPEZA DE ARQUIVOS TEMPORÁRIOS[/bold red]\n\n"
        "Locais afetados:\n"
        " 1. C:\\Windows\\Temp\n"
        " 2. AppData\\Local\\Temp (de TODOS os perfis de usuários)\n"
        " 3. C:\\Windows\\SoftwareDistribution\\Download\n"
        " 4. C:\\Windows\\SoftwareDistribution.k* (Pastas do Kaspersky)\n"
        " 5. Lixeira do sistema (C:\\$Recycle.Bin)\n\n"
        "[yellow]Nenhum backup será gerado.[/yellow]",
        title="Atenção", border_style="red"
    ))

    console.print(f"[bold blue][*] Consultando espaço livre atual na unidade C:...[/bold blue]")
    free_before = get_free_space_bytes(ip, user, password, domain)

    if free_before is not None:
        free_before_gb = free_before / (1024**3)
        free_before_mb = free_before / (1024**2)
        console.print(f"  [bold green][i] Espaço livre no disco C: {free_before_gb:.2f} GB ({free_before_mb:,.0f} MB)[/bold green]\n")

    confirmar = console.input("[bold yellow]Deseja prosseguir com a exclusão? (s/N): [/bold yellow]").strip().lower()
    if confirmar != 's':
        console.print("[yellow]Operação de limpeza cancelada.[/yellow]")
        return

    console.print(f"\n[bold blue][*] Executando rotina de exclusão remota...[/bold blue]")

    ps_clean_script = """
    $ErrorActionPreference = 'SilentlyContinue'

    Write-Output "[CLEAN] Esvaziando Lixeira do sistema..."
    Clear-RecycleBin -Force -ErrorAction SilentlyContinue

    Write-Output "[CLEAN] Limpando C:\\Windows\\Temp..."
    Remove-Item -Path "C:\\Windows\\Temp\\*" -Recurse -Force -ErrorAction SilentlyContinue

    Write-Output "[CLEAN] Limpando C:\\Windows\\SoftwareDistribution\\Download..."
    Remove-Item -Path "C:\\Windows\\SoftwareDistribution\\Download\\*" -Recurse -Force -ErrorAction SilentlyContinue

    $klFolders = Get-ChildItem -Path "C:\\Windows" -Directory -Filter "SoftwareDistribution.k*" -ErrorAction SilentlyContinue
    foreach ($kl in $klFolders) {
        Write-Output ("[CLEAN] Removendo pasta do Kaspersky: " + $kl.FullName)
        Remove-Item -Path $kl.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Output "[CLEAN] Limpando AppData\\Local\\Temp de todos os perfis..."
    $userProfiles = Get-ChildItem -Path "C:\\Users" -Directory -ErrorAction SilentlyContinue
    foreach ($profile in $userProfiles) {
        $tempPath = Join-Path -Path $profile.FullName -ChildPath "AppData\\Local\\Temp"
        if (Test-Path -Path $tempPath) {
            Remove-Item -Path "$tempPath\\*" -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    Write-Output "[CLEAN] Processo de limpeza concluído no alvo."
    """

    encoded_ps = base64.b64encode(ps_clean_script.encode('utf-16le')).decode('utf-8')
    cmd = ["nxc", "smb", ip, "-u", user, "-p", password, "-d", domain, "-x", f"powershell -NoProfile -EncodedCommand {encoded_ps}"]
    output = run_nxc_command(cmd)

    if output:
        for line in output.splitlines():
            if "[CLEAN]" in line:
                clean_line = line.split("[CLEAN]")[1].strip()
                console.print(f"  [bold green][+][/bold green] {clean_line}")

    console.print(f"\n[bold blue][*] Verificando espaço livre no C: DEPOIS da limpeza...[/bold blue]")
    free_after = get_free_space_bytes(ip, user, password, domain)

    if free_before is not None and free_after is not None:
        liberado_bytes = free_after - free_before
        if liberado_bytes < 0: liberado_bytes = 0

        liberado_mb = liberado_bytes / (1024**2)
        liberado_gb = liberado_bytes / (1024**3)

        before_gb = free_before / (1024**3)
        after_gb = free_after / (1024**3)

        table = Table(title="RESUMO DA LIBERAÇÃO DE ESPAÇO (C:)", border_style="green", box=box.ROUNDED)
        table.add_column("Descrição", style="bold white")
        table.add_column("Espaço", justify="right", style="bold green")

        table.add_row("Espaço Livre Antes", f"{before_gb:.2f} GB")
        table.add_row("Espaço Livre Depois", f"{after_gb:.2f} GB")
        table.add_row("Total Liberado no Disco", f"{liberado_gb:.2f} GB ({liberado_mb:,.2f} MB)")

        console.print(table)
    else:
        console.print("[yellow][!] Não foi possível calcular a diferença de espaço.[/yellow]")

def menu_disco(ip, user, password, domain):
    """Submenu de gerenciamento de disco."""
    if not checar_credenciais(user): return
    while True:
        clear_screen()
        console.print(Panel(f"[bold cyan]GERENCIAR DISCO ({ip})[/bold cyan]", border_style="blue"))
        console.print("[yellow]1.[/yellow] Verificar Espaço em Disco (Apenas C:)")
        console.print("[yellow]2.[/yellow] Limpar Arquivos Temporários (Liberação de Disco)")
        console.print("[red]0.[/red] Voltar ao Menu Principal\n")

        opcao = console.input("[bold]Escolha uma opção: [/bold]").strip()

        if opcao == '1': check_disk_space(ip, user, password, domain)
        elif opcao == '2': clean_temp_files(ip, user, password, domain)
        elif opcao == '0': break
        else: console.print("[red]Opção inválida![/red]")

        if opcao != '0': console.input("\n[dim yellow]Pressione ENTER para continuar...[/dim yellow]")

def list_running_services(ip, user, password, domain):
    if not checar_credenciais(user): return
    console.print(f"\n[bold blue][*] Consultando Serviços em Execução via WMI...[/bold blue]")
    cmd = ["nxc", "smb", ip, "-u", user, "-p", password, "-d", domain, "--wmi-query", "Select DisplayName, Name From Win32_Service Where State='Running'"]
    output = run_nxc_command(cmd)
    if not output: return

    table = Table(title="Serviços em Execução", border_style="green", box=box.ROUNDED, expand=True)
    table.add_column("Nome / DisplayName", style="bold white")

    encontrou = False
    for line in output.splitlines():
        if "DisplayName" in line and "Name" in line:
            clean_line = re.sub(r'^SMB\s+[\d\.]+\s+\d+\s+[A-Za-z0-9_-]+\s+', '', line).strip()
            table.add_row(clean_line)
            encontrou = True

    if encontrou:
        console.print(table)
    else:
        console.print("[yellow]Nenhum serviço encontrado.[/yellow]")

def list_shares(ip, user, password, domain):
    if not checar_credenciais(user): return
    console.print(f"\n[bold blue][*] Listando Pastas Compartilhadas (--shares)...[/bold blue]")
    cmd = ["nxc", "smb", ip, "-u", user, "-p", password, "-d", domain, "--shares"]
    output = run_nxc_command(cmd)
    if not output: return

    table = Table(title="Pastas Compartilhadas Descobertas", border_style="bright_blue", box=box.ROUNDED, expand=True)
    table.add_column("Nome da Compartilhamento", style="bold white")
    table.add_column("Permissões", justify="center")
    table.add_column("Descrição / Remark", style="dim white")

    encontrou = False
    for line in output.splitlines():
        clean_line = re.sub(r'^SMB\s+[\d\.]+\s+\d+\s+[A-Za-z0-9_-]+\s+', '', line).strip()

        if not clean_line or "Share" in clean_line or "---" in clean_line or "[+]" in clean_line:
            continue

        match = re.search(r'^(.+?)\s+(READ,WRITE|READ|WRITE|NO ACCESS)(?:\s+(.*))?$', clean_line)
        if match:
            share_name = match.group(1).strip()
            perms = match.group(2).strip()
            remark = match.group(3).strip() if match.group(3) else ""

            cor_perm = "bold green" if "READ" in perms or "WRITE" in perms else "bold red"
            table.add_row(share_name, f"[{cor_perm}]{perms}[/]", remark)
            encontrou = True

    if encontrou:
        console.print(table)
    else:
        console.print("[yellow]Não foram encontradas pastas compartilhadas visíveis.[/yellow]")

def get_loggedon_users(ip, user, password, domain):
    if not checar_credenciais(user): return
    console.print(f"\n[bold blue][*] Verificando usuários com sessão ativa no momento...[/bold blue]")
    cmd = ["nxc", "smb", ip, "-u", user, "-p", password, "-d", domain, "--loggedon-users"]
    output = run_nxc_command(cmd)
    if not output: return

    table = Table(title="Usuários Logados", border_style="green", box=box.ROUNDED)
    table.add_column("Usuário", style="bold white")

    encontrou = False
    for line in output.splitlines():
        clean_line = re.sub(r'^SMB\s+[\d\.]+\s+\d+\s+[A-Za-z0-9_-]+\s+', '', line).strip()
        if not clean_line: continue

        if "users:" in clean_line.lower():
            match = re.search(r'users:\s*(.+)', clean_line, re.IGNORECASE)
            if match:
                usuarios = match.group(1).strip()
                if usuarios:
                    for u in usuarios.split(','):
                        table.add_row(u.strip('[] '))
                        encontrou = True
            continue

        if "\\" in clean_line and "Pwn3d" not in clean_line and not clean_line.startswith("["):
            table.add_row(clean_line)
            encontrou = True

    if not encontrou:
        cmd_wmi = ["nxc", "smb", ip, "-u", user, "-p", password, "-d", domain, "--wmi-query", "Select UserName from Win32_ComputerSystem"]
        out_wmi = run_nxc_command(cmd_wmi, silent_error=True)
        if out_wmi:
            for line in out_wmi.splitlines():
                match = re.search(r'UserName\s*(?:=>|:)\s*(.+)', line, re.IGNORECASE)
                if match:
                    user_wmi = match.group(1).strip()
                    if user_wmi and user_wmi != "None":
                        table.add_row(f"{user_wmi} (Sessão Interativa/Console)")
                        encontrou = True

    if encontrou:
        console.print(table)
    else:
        console.print("[yellow]Nenhum usuário ativo encontrado no momento.[/yellow]")

def reboot_machine(ip, user, password, domain):
    if not checar_credenciais(user): return
    console.print(Panel(f"[bold red]ATENÇÃO: A máquina {ip} será reiniciada imediatamente.[/bold red]", border_style="red"))
    confirmar = console.input("[bold yellow]Tem certeza? (s/N): [/bold yellow]").strip().lower()
    if confirmar == 's':
        console.print(f"\n[bold blue][*] Enviando comando de reinicialização (shutdown /r /t 0 /f) via NXC...[/bold blue]")
        cmd = ["nxc", "smb", ip, "-u", user, "-p", password, "-d", domain, "-x", "shutdown /r /t 0 /f"]
        run_nxc_command(cmd, silent_error=True)
        console.print("[bold green][+] Comando de reinicialização enviado! O alvo deve reiniciar em breve.[/bold green]\n")
    else:
        console.print("[yellow]Reinicialização cancelada.[/yellow]")

# ==========================================
# MÓDULO: Rede & Diagnóstico (Super Ping / Tracepath)
# ==========================================
def calcular_jitter(tempos):
    if len(tempos) < 2: return 0.0
    diferencas = [abs(tempos[i] - tempos[i-1]) for i in range(1, len(tempos))]
    return sum(diferencas) / len(diferencas)

def gerar_painel_stats(stats):
    total = stats["enviados"]
    if total == 0: return Panel("Aguardando dados... (Pressione 'F' para parar)", title=" Estatísticas", border_style="cyan")

    tempos = stats["tempos"]
    media_ms = (sum(tempos) / len(tempos)) if tempos else 0.0
    perdidos = stats["perdidos"]
    perda_percent = (perdidos / total * 100) if total > 0 else 0.0

    texto = Text()
    texto.append("Enviados: ", style="bold white"); texto.append(f"{total} | ", style="green")
    texto.append("Ótimo (<50ms): ", style="bold white"); texto.append(f"{stats['otimo']} | ", style="green")
    texto.append("Perdidos: ", style="bold white"); texto.append(f"{perdidos}\n", style="magenta")
    texto.append("Latência Média: ", style="bold white"); texto.append(f"{media_ms:.1f} ms | ", style="cyan")
    texto.append("Jitter: ", style="bold white"); texto.append(f"{calcular_jitter(tempos):.1f}ms | ", style="cyan")
    perda_style = "bold red" if perda_percent > 1 else "green"
    texto.append("Perda: ", style="bold white"); texto.append(f"{perda_percent:.1f}%", style=perda_style)

    return Panel(texto, title=" Estatísticas (Pressione 'F' para parar)", border_style="cyan", expand=True)

def criar_tabela_ping(host, historico):
    table = Table(title=f" Monitorando Ping: [bold cyan]{host}[/bold cyan]", border_style="bright_blue", expand=True, box=box.ROUNDED)
    table.add_column("Seq", justify="center", style="dim", width=6)
    table.add_column("Tempo (ms)", justify="right")
    table.add_column("Status", justify="center")
    table.add_column("Jitter", justify="right", style="cyan")
    table.add_column("Hora", justify="center", style="dim")
    for linha in historico: table.add_row(*linha)
    return table

def renderizar_interface_ping(host, historico, stats):
    layout = Layout()
    layout.split(Layout(gerar_painel_stats(stats), size=5), Layout(criar_tabela_ping(host, historico)))
    return layout

def executar_ping_detalhado(ip_padrao=None):
    clear_screen()
    if ip_padrao:
        host = ip_padrao
    else:
        host = console.input("[cyan]Digite o Host/IP para o monitoramento: [/cyan]").strip()
    if not host: return

    comando = ["ping", "-n", "-i", "1", "-W", "2", host]
    try:
        processo = subprocess.Popen(comando, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)
    except FileNotFoundError:
        console.print("[bold red]Erro: 'ping' não encontrado.[/bold red]"); time.sleep(2); return

    historico = deque(maxlen=MAX_LINHAS)
    stats = {"enviados": 0, "otimo": 0, "mediano": 0, "alto": 0, "perdidos": 0, "tempos": []}
    seq_esperada = 1

    fila_saida = queue.Queue()
    thread_leitura = threading.Thread(target=ler_saida_subprocesso, args=(processo, fila_saida), daemon=True)
    thread_leitura.start()

    inicio_dt = datetime.now()

    try:
        with Live(renderizar_interface_ping(host, historico, stats), console=console, refresh_per_second=10, transient=True) as live:
            while processo.poll() is None or not fila_saida.empty():
                char = getch_char_non_blocking()
                if char and char.lower() == 'f':
                    processo.terminate()
                    break

                while not fila_saida.empty():
                    linha = fila_saida.get_nowait()
                    hora_atual = datetime.now().strftime("%H:%M:%S")

                    match_tempo = re.search(r"time=([\d.]+)\s*ms", linha)
                    match_seq = re.search(r"icmp_seq=(\d+)", linha)

                    if match_tempo and match_seq:
                        tempo_ms, seq_atual = float(match_tempo.group(1)), int(match_seq.group(1))

                        while seq_esperada < seq_atual:
                            stats["enviados"] += 1; stats["perdidos"] += 1
                            historico.append((f"[red]{seq_esperada}[/]", "-", "[bold red]Perdido[/]", "-", hora_atual))
                            seq_esperada += 1

                        stats["enviados"] += 1; stats["tempos"].append(tempo_ms)
                        seq_esperada = seq_atual + 1
                        jitter_inst = abs(tempo_ms - stats["tempos"][-2]) if len(stats["tempos"]) > 1 else 0.0

                        if tempo_ms < LIMIAR_OTIMO: cor, status_txt, stats["otimo"] = "green", "Ótimo", stats["otimo"] + 1
                        elif tempo_ms < LIMIAR_MEDIANO: cor, status_txt, stats["mediano"] = "yellow", "Mediano", stats["mediano"] + 1
                        else: cor, status_txt, stats["alto"] = "red", "Alto", stats["alto"] + 1

                        historico.append((f"[{cor}]{seq_atual}[/]", f"[bold {cor}]{tempo_ms:.1f}[/]", f"[{cor}]{status_txt}[/]", f"{jitter_inst:.1f}", hora_atual))

                    elif any(err in linha.lower() for err in ["timeout", "unreachable", "fail"]):
                        stats["enviados"] += 1; stats["perdidos"] += 1
                        historico.append((f"[red]{seq_esperada}[/]", "-", "[bold red]Falha[/]", "-", hora_atual))
                        seq_esperada += 1

                live.update(renderizar_interface_ping(host, historico, stats))
                time.sleep(0.1)
    except KeyboardInterrupt:
        processo.terminate()
    finally:
        processo.kill()
        thread_leitura.join(timeout=0.5)
        clear_screen()
        exibir_e_perguntar_salvar_relatorio_ping(host, stats, inicio_dt)

def criar_tabela_tracepath(host, historico):
    table = Table(title=f"Rastreando Rota para: [bold cyan]{host}[/bold cyan]\n[dim]Pressione 'F' para interromper[/dim]", border_style="bright_blue", expand=True, box=box.ROUNDED)
    table.add_column("Salto", justify="center", style="bold white", width=6)
    table.add_column("IP / Host", justify="left")
    table.add_column("Tempo", justify="right")
    table.add_column("Status / Informação", justify="center")
    for linha in historico: table.add_row(*linha)
    return table

def executar_tracepath_grafico(ip_padrao=None):
    clear_screen()
    if ip_padrao:
        host = ip_padrao
    else:
        host = console.input("[cyan]Digite o Host/IP para rastrear a rota: [/cyan]").strip()
    if not host: return

    comando = ["tracepath", "-n", host]
    try:
        processo = subprocess.Popen(comando, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)
    except FileNotFoundError:
        console.print("[bold red]Erro: 'tracepath' não encontrado.[/bold red]"); time.sleep(2); return

    historico_trace = []
    fila_saida = queue.Queue()
    thread_leitura = threading.Thread(target=ler_saida_subprocesso, args=(processo, fila_saida), daemon=True)
    thread_leitura.start()

    try:
        with Live(criar_tabela_tracepath(host, historico_trace), console=console, refresh_per_second=10) as live:
            while processo.poll() is None or not fila_saida.empty():
                char = getch_char_non_blocking()
                if char and char.lower() == 'f':
                    processo.terminate()
                    break

                while not fila_saida.empty():
                    linha = fila_saida.get_nowait().strip()
                    if not linha: continue

                    hop_match = re.match(r"^\s*(\d+)\??:\s+(.*)", linha)
                    if hop_match:
                        hop, rest = hop_match.group(1), hop_match.group(2).strip()
                        ip, tempo_fmt, status = "N/A", "-", "[red]Sem Resposta[/red]"

                        if "no reply" not in rest and "[LOCALHOST]" not in rest:
                            parts = rest.split()
                            ip = parts[0]
                            tempo_val_str = next((p for p in parts if "ms" in p), None)

                            if tempo_val_str:
                                try:
                                    t_float = float(tempo_val_str.replace("ms", ""))
                                    if t_float < 50: cor = "green"
                                    elif t_float < 150: cor = "yellow"
                                    else: cor = "red"
                                    tempo_fmt = f"[{cor}]{t_float:.1f}ms[/]"
                                except ValueError:
                                    tempo_fmt = tempo_val_str

                            status = "[green]OK[/green]"
                            if "reached" in rest: status = "[bold green]Destino Alcançado[/bold green]"

                        historico_trace.append((hop, ip, tempo_fmt, status))

                live.update(criar_tabela_tracepath(host, historico_trace))
                time.sleep(0.1)
    except KeyboardInterrupt:
        processo.terminate()
    finally:
        processo.kill()
        thread_leitura.join(timeout=0.5)
        clear_screen()
        console.print(criar_tabela_tracepath(host, historico_trace))
        exibir_e_perguntar_salvar_tracepath(host, historico_trace)

def verificar_multiplos_ips():
    clear_screen()
    console.print(Panel("[bold cyan]Verificação Rápida de Múltiplos IPs[/bold cyan]", border_style="blue"))
    nome_arquivo = console.input("[cyan]Digite o nome do arquivo de IPs (padrão: ips.txt): [/cyan]").strip() or 'ips.txt'

    if not os.path.exists(nome_arquivo):
        console.print(f"[bold red]Erro: Arquivo '{nome_arquivo}' não encontrado![/bold red]")
        with open(nome_arquivo, "w") as f: f.write("8.8.8.8\n1.1.1.1\n")
        console.print(f"Um arquivo de exemplo '[green]{nome_arquivo}[/green]' foi criado.")
        time.sleep(2); return

    console.print(f"\n[cyan]Lendo IPs de '{nome_arquivo}'...[/cyan]\n")
    table = Table(title=f"Status dos IPs ({nome_arquivo})", border_style="bright_blue", box=box.ROUNDED)
    table.add_column("Endereço IP", style="bold white")
    table.add_column("Status", justify="center")

    log_buffer = []
    with open(nome_arquivo, 'r') as f:
        for ip in f:
            ip = ip.strip()
            if not ip: continue

            comando = ['ping', '-c', '1', '-W', '2', ip]
            resultado = subprocess.run(comando, capture_output=True, text=True)

            if resultado.returncode == 0:
                table.add_row(ip, "[bold green]RESPONDENDO (ON)[/bold green]")
                log_buffer.append(f"IP {ip:<15} - ON")
            else:
                table.add_row(ip, "[bold red]NÃO RESPONDE (OFF)[/bold red]")
                log_buffer.append(f"IP {ip:<15} - OFF")

    console.print(table)
    try:
        resposta = console.input("\n[bold yellow]Deseja salvar este resumo? (S/N): [/bold yellow]").strip().lower()
    except (KeyboardInterrupt, EOFError):
        resposta = 'n'

    if resposta == 's':
        nome_arquivo_log = f"relatorio_ips_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(nome_arquivo_log, 'w', encoding='utf-8') as f: f.write("\n".join(log_buffer))
        console.print(f"[bold green]💾 Relatório salvo em: {nome_arquivo_log}[/bold green]")
        time.sleep(1)

def exibir_e_perguntar_salvar_relatorio_ping(host, stats, inicio_dt):
    fim_dt, total = datetime.now(), stats["enviados"]
    if total == 0:
        console.print("\n[bold yellow]Nenhum pacote processado.[/bold yellow]"); time.sleep(2)
        return

    duracao = str(fim_dt - inicio_dt).split(".")[0]
    tempos, perdidos = stats["tempos"], stats["perdidos"]
    media_ms = (sum(tempos) / len(tempos)) if tempos else 0.0
    min_ms, max_ms = (min(tempos), max(tempos)) if tempos else (0.0, 0.0)
    jitter_ms = calcular_jitter(tempos)
    perda_percent = (perdidos / total * 100) if total > 0 else 0.0

    tabela = Table(title="RELATÓRIO FINAL DE MONITORAMENTO", border_style="bold green", box=box.ROUNDED)
    tabela.add_column("Métrica", style="bold cyan"); tabela.add_column("Valor", style="bold white")
    tabela.add_row("Alvo Monitorado", host)
    tabela.add_row("Início / Fim", f"{inicio_dt.strftime('%H:%M:%S')} ➔ {fim_dt.strftime('%H:%M:%S')}")
    tabela.add_row("Duração Total", duracao)
    tabela.add_row("Pacotes Enviados / Perdidos", f"{total} / {perdidos} ({perda_percent:.1f}%)")
    tabela.add_row("Latência Mín / Máx / Média", f"{min_ms:.1f} ms / {max_ms:.1f} ms / {media_ms:.1f} ms")
    tabela.add_row("Jitter Médio", f"{jitter_ms:.1f} ms")
    console.print(tabela)

    try:
        resposta = console.input("\n[bold yellow]Deseja salvar este relatório? (S/N): [/bold yellow]").strip().lower()
    except (KeyboardInterrupt, EOFError):
        resposta = 'n'

    if resposta == 's':
        nome = f"log_ping_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(nome, "w", encoding="utf-8") as f:
             f.write(f"RELATÓRIO DE PING - {host}\n"
                    f"Período: {inicio_dt.strftime('%d/%m/%Y %H:%M:%S')} a {fim_dt.strftime('%d/%m/%Y %H:%M:%S')}\n"
                    f"Enviados: {total} | Perdidos: {perdidos}\n"
                    f"Latência Média: {media_ms:.1f}ms | Jitter: {jitter_ms:.1f}ms\n")
        console.print(f"[dim]Relatório salvo em: [bold white]{nome}[/bold white][/dim]\n")
        time.sleep(1)

def exibir_e_perguntar_salvar_tracepath(host, historico):
    try:
        resposta = console.input("\n[bold yellow]Deseja salvar este relatório de rota? (S/N): [/bold yellow]").strip().lower()
    except (KeyboardInterrupt, EOFError):
        resposta = 'n'

    if resposta == 's':
        nome_arquivo = f"log_tracepath_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        tag_re = re.compile(r'\[[^\]]*\]')
        with open(nome_arquivo, "w", encoding="utf-8") as f:
            f.write(f"RELATÓRIO DE TRACEPATH - {host}\n{'='*40}\n")
            for hop, ip, tempo, status in historico:
                f.write(f"Salto {tag_re.sub('', hop):<3} | {tag_re.sub('', ip):<18} | {tag_re.sub('', tempo):<12} | {tag_re.sub('', status)}\n")
        console.print(f"[dim]Relatório salvo em: [bold white]{nome_arquivo}[/bold white][/dim]\n")
        time.sleep(1)

# ==========================================
# Menu Principal Unificado
# ==========================================
def main():
    if platform.system() == "Windows":
        console.print("[bold red]Ferramenta otimizada para Linux/Parrot OS. Encerrando.[/bold red]"); sys.exit(1)

    clear_screen()
    console.print(Panel("[bold cyan]CENTRAL DE ADMINISTRAÇÃO E DIAGNÓSTICO DE REDE[/bold cyan]", border_style="blue"))

    try:
        ip = console.input("[cyan]Endereço IP / Host alvo (ex: 8.8.8.8 ou 10.100.112.191): [/cyan]").strip()
        if not ip: return

        domain = ""
        user = ""
        password = ""

        if eh_ip_privado(ip):
            console.print("[bold yellow][i] IP Privado Detectado (Rede Interna) - Solicitando credenciais SMB...[/i][/bold yellow]")
            domain = console.input("[cyan]Domínio [jacomarsm]: [/cyan]").strip() or "jacomarsm"
            user = console.input("[cyan]Usuário [administrador]: [/cyan]").strip() or "administrador"
            password = getpass.getpass(f"Senha para {domain}\\{user}: ")
        else:
            console.print("[bold green][i] IP Público Detectado - Modo de Diagnóstico ICMP/Rede Ativado.[/i][/bold green]")

    except KeyboardInterrupt:
        console.print("\n[yellow]Saindo...[/yellow]")
        sys.exit(0)

    while True:
        clear_screen()
        info_credencial = f" | [dim white]{domain}\\{user}[/dim white]" if user else " | [bold green]Modo Público[/bold green]"
        console.print(Panel(f"[bold cyan]MENU PRINCIPAL ALVO: {ip}[/bold cyan]{info_credencial}", border_style="bright_blue"))

        console.print("[bold yellow]--- ADMINISTRAÇÃO REMOTA WINDOWS (REDE INTERNA) ---[/bold yellow]")
        console.print("  [yellow]1.[/yellow] Verificar Uptime")
        console.print("  [yellow]2.[/yellow] Gerenciar Programas Instalados...")
        console.print("  [yellow]3.[/yellow] Gerenciar Disco...")
        console.print("  [yellow]4.[/yellow] Listar Serviços em Execução")
        console.print("  [yellow]5.[/yellow] Listar Pastas Compartilhadas")
        console.print("  [yellow]6.[/yellow] Usuários Logados")
        console.print("  [yellow]7.[/yellow] Reiniciar Máquina remotamente")
        console.print("  [yellow]8.[/yellow] Trocar Alvo (IP/Credenciais)\n")

        console.print("[bold cyan]--- DIAGNÓSTICO DE REDE LOCAL / ICMP ---[/bold cyan]")
        console.print(f"  [cyan]9.[/cyan] Monitorar Ping Contínuo ao Alvo ({ip})")
        console.print(f"  [cyan]10.[/cyan] Rastrear Rota Tracepath ao Alvo ({ip})")
        console.print("  [cyan]11.[/cyan] Verificar Múltiplos IPs de um Arquivo\n")

        console.print("  [bold red]0.[/bold red] Sair\n")

        try:
            opcao = console.input("[bold]Escolha uma opção: [/bold]").strip()
        except KeyboardInterrupt:
            console.print("\n[yellow]Saindo...[/yellow]")
            break

        if opcao == '1': check_uptime(ip, user, password, domain)
        elif opcao == '2': menu_programas(ip, user, password, domain)
        elif opcao == '3': menu_disco(ip, user, password, domain)
        elif opcao == '4': list_running_services(ip, user, password, domain)
        elif opcao == '5': list_shares(ip, user, password, domain)
        elif opcao == '6': get_loggedon_users(ip, user, password, domain)
        elif opcao == '7': reboot_machine(ip, user, password, domain)
        elif opcao == '8':
            main()
            break
        elif opcao == '9': executar_ping_detalhado(ip)
        elif opcao == '10': executar_tracepath_grafico(ip)
        elif opcao == '11': verificar_multiplos_ips()
        elif opcao == '0':
            console.print("[bold green]Saindo... Até logo![/bold green]")
            break
        else:
            console.print("[red]Opção inválida![/red]")

        if opcao not in ['2', '3', '8', '0']:
            console.input("\n[dim yellow]Pressione ENTER para continuar...[/dim yellow]")

if __name__ == "__main__":
    main()
