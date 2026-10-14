#!/usr/bin/env python3
##################################################################################################################
#Nome do Script		:  analisar_arquivos.py
#Descrição	     	:  Automação de Triagem Estática e Análise Forense (Oletools, PDFid & PDF-Parser)
#Autor       		:  Maurício Paim
#Email         		:  paim.mauricio@gmail.com
#Versao             : v1.0.0
#Data                : Maio 2026
###################################################################################################################


import os
import sys
import shutil
import subprocess
import re

# Importações do pacote oletools
try:
    from oletools.olevba import VBA_Parser
    from oletools.oleid import OleID
    from oletools.rtfobj import RtfObjParser
except ImportError as e:
    print(f"❌ Erro de importação: {e}")
    print("O pacote 'oletools' não foi encontrado ou falhou ao carregar.")
    print("Instale-o usando: sudo pip3 install oletools --break-system-packages")
    sys.exit(1)

def identificar_tipo_arquivo(caminho_arquivo):
    """Identifica o tipo real do arquivo lendo seus bytes iniciais (Magic Bytes)"""
    try:
        with open(caminho_arquivo, 'rb') as f:
            header = f.read(4)

            if header.startswith(b'%PDF'):
                return 'PDF'
            elif header.startswith(b'{\\rtf'):
                return 'RTF'
            elif header.startswith(b'\xd0\xcf\x11\xe0'):
                return 'OFFICE_ANTIGO'  # OLE2 (doc, xls antigos)
            elif header.startswith(b'PK\x03\x04'):
                ext = os.path.splitext(caminho_arquivo)[1].lower()
                if ext in ['.docx', '.xlsx', '.pptx', '.docm', '.xlsm', '.pptm']:
                    return 'OFFICE_MODERNO'
                return 'ZIP_COMUM'
            else:
                return 'DESCONHECIDO'
    except Exception as e:
        return f'ERRO: {str(e)}'

def extrair_conteudo_objeto_pdf(caminho_arquivo, tag_suspeita):
    """Busca o objeto associado à tag suspeita e analisa suas referências profundas de forma automatizada"""
    cmd_parser = shutil.which('pdf-parser') or shutil.which('pdf-parser.py')
    if not cmd_parser:
        return None

    try:
        # 1. Procura quais objetos contêm a tag suspeita (ex: OpenAction ou JavaScript)
        res_busca = subprocess.run(
            [cmd_parser, '--search', tag_suspeita.replace('/', ''), caminho_arquivo],
            capture_output=True, text=True, check=True
        )

        saida_busca = res_busca.stdout
        objetos = re.findall(r'obj\s+(\d+)', saida_busca)

        if not objetos:
            return None

        conteudo_extraido = []
        for obj_id in set(objetos)[:2]:
            # Extrai o objeto inicial onde a tag foi encontrada
            res_inicial = subprocess.run(
                [cmd_parser, '--object', obj_id, '--filter', '--raw', caminho_arquivo],
                capture_output=True, text=True, check=True
            )

            conteudo_bruto = res_inicial.stdout.strip()

            # Inteligência Forense: Verifica se este objeto aponta para outro objeto (ex: "8 0 R")
            referencias = re.findall(r'(\d+)\s+0\s+R', conteudo_bruto)

            # Se ele apenas apontar para outro objeto, seguimos a referência de forma recursiva!
            if referencias:
                for ref_id in set(referencias):
                    res_ref = subprocess.run(
                        [cmd_parser, '--object', ref_id, '--filter', '--raw', caminho_arquivo],
                        capture_output=True, text=True, check=True
                    )
                    dados_ref = res_ref.stdout.strip()
                    if dados_ref:
                        conteudo_extraido.append((ref_id, f"↳ [Seguindo Referência do Objeto {obj_id}]:\n{dados_ref}"))
            else:
                # Se ele já contiver o código bruto diretamente, extraímos daqui mesmo
                if conteudo_bruto:
                    conteudo_extraido.append((obj_id, conteudo_bruto))

        return conteudo_extraido
    except Exception:
        return None

def analisar_pdf(caminho_arquivo):
    print("TIPO DETECTADO: Documento PDF")
    print("👉 PDFs comuns não possuem macros VBA, mas podem esconder scripts perigosos.")
    print("-" * 60)

    cmd_pdfid = shutil.which('pdfid') or shutil.which('pdfid.py')

    if cmd_pdfid:
        try:
            res = subprocess.run([cmd_pdfid, caminho_arquivo], capture_output=True, text=True, check=True)
            pdf_status = res.stdout
            tags_encontradas = []

            mapa_ameacas = {
                '/JavaScript': "• Scripts Ativos (/JavaScript): Tenta executar códigos de programação dentro do PDF.",
                '/JS': "• Códigos de Programação (/JS): Contém rotinas que rodam ao interagir com o arquivo.",
                '/AA': "• Ação Automática (/AA): Tenta rodar comandos escondidos assim que você abre o documento.",
                '/Launch': "• Abertura de Aplicativos (/Launch): Tenta abrir outros programas ou arquivos sem sua permissão.",
                '/OpenAction': "• Ação de Abertura (/OpenAction): Executa ações automatizadas no primeiro frame do documento."
            }

            for linha in pdf_status.splitlines():
                for chave, explicacao in mapa_ameacas.items():
                    if chave in linha:
                        partes = linha.split()
                        for parte in partes:
                            if parte.isdigit() and int(parte) > 0:
                                tags_encontradas.append(chave)

            if tags_encontradas:
                print("PERIGO: ELEMENTOS ATIVOS ENCONTRADOS NO PDF!")
                print("RECOMENDAÇÃO: Cuidado extremo! Este PDF possui recursos automatizados suspeitos.")
                print("-" * 60)

                for tag in set(tags_encontradas):
                    print(mapa_ameacas[tag])

                print("-" * 60)
                print("INICIANDO DISSECAÇÃO FORENSE AUTOMÁTICA...")
                print("👉 Buscando e seguindo as referências ocultas dos objetos do PDF...")
                print("-" * 60)

                dissecou_algo = False
                for tag in set(tags_encontradas):
                    dados_objetos = extrair_conteudo_objeto_pdf(caminho_arquivo, tag)
                    if dados_objetos:
                        for obj_id, conteudo in dados_objetos:
                            dissecou_algo = True
                            print(f"\nConteúdo extraído do [Objeto {obj_id}] (Relacionado a {tag}):")
                            print("=" * 60)
                            linhas = conteudo.splitlines()
                            for linha in linhas[:20]:  # Exibe até 20 linhas para melhor visibilidade
                                print(f"  {linha}")
                            if len(linhas) > 20:
                                print("  [... Conteúdo muito longo. Use o pdf-parser manualmente se precisar ler tudo ...]")
                            print("=" * 60)

                if not dissecou_algo:
                    print("⚠️ Não foi possível extrair o conteúdo legível dos objetos automaticamente.")
                    print("Os alvos podem estar protegidos ou as referências são apenas de posicionamento estático.")
                else:
                    print("\n💡 Dica Forense: Analise o conteúdo do objeto acima para verificar se há comandos ou links ocultos.")

            else:
                print("RESULTADO: Documento PDF aparentemente limpo!")
                print("Não foram encontrados elementos ativos suspeitos comumente usados em ataques cibernéticos.")

        except Exception as e:
            print(f"⚠️ Erro ao processar o utilitário pdfid: {e}")
    else:
        print("💡 Resumo básico:")
        print("O arquivo físico é de fato um PDF estrutural estável.")
        print("Recomenda-se abri-lo sempre em um leitor de PDFs atualizado e com JavaScript desativado por segurança.")

def analisar_rtf(caminho_arquivo):
    print("⚠️ TIPO DETECTADO: Documento RTF (Rich Text Format)")
    print("👉 Arquivos RTF costumam ser usados por atacantes para esconder exploits ou anexos maliciosos.")
    print("-" * 60)

    try:
        rtf_parser = RtfObjParser(caminho_arquivo)
        rtf_parser.parse()

        if len(rtf_parser.objects) > 0:
            print(f"ALERTA: Foram encontrados {len(rtf_parser.objects)} objeto(s) embutido(s) neste arquivo RTF!")
            print("👉 Isso é altamente suspeito e indica potencial tentativa de infecção automática.")
            for i, obj in enumerate(rtf_parser.objects):
                print(f"   • Objeto #{i+1}: Classe '{obj.class_name}' | Tamanho: {obj.size} bytes")
        else:
            print("RESULTADO: Nenhum objeto oculto ou arquivo malicioso embutido foi encontrado neste RTF.")
    except Exception as e:
        print(f"❌ Não foi possível analisar os objetos do RTF: {str(e)}")

def analisar_office(caminho_arquivo, tipo):
    if tipo == 'OFFICE_ANTIGO':
        print("TIPO DETECTADO: Documento antigo do Microsoft Office (Formato OLE / Word 97-2003)")
    else:
        print("TIPO DETECTADO: Documento moderno do Microsoft Office (Formato OpenXML / docx, docm, xlsx, etc.)")
    print("-" * 60)

    try:
        oid = OleID(caminho_arquivo)
        indicadores = oid.check()

        criptografado = False
        for id_obj in indicadores:
            if id_obj.id == 'encrypted' and id_obj.value is True:
                criptografado = True

        if criptografado:
            print("🔒 ARQUIVO CRIPTOGRAFADO: Este documento está protegido por senha.")
            print("👉 Cuidado! Malwares frequentemente usam senhas para impedir varreduras de segurança.")
            print("-" * 60)
    except Exception as e:
        print(f"⚠️ Alerta ao extrair dados de criptografia: {str(e)}")

    try:
        parser = VBA_Parser(caminho_arquivo)
        if parser.detect_vba_macros():
            print("⚠️ ALERTA DE SEGURANÇA: Este documento contém códigos ativos de programação (Macros).")
            print("👉 Ações suspeitas identificadas:")

            resultados = parser.analyze_macros()
            criticos = []
            if resultados:
                for tipo_macro, keyword, descricao in resultados:
                    if tipo_macro in ['AutoExec', 'IOC']:
                        criticos.append(f"   • {tipo_macro}: {keyword} ({descricao})")
                    elif tipo_macro == 'Suspicious':
                        print(f"   • Comportamento Suspeito: {keyword} ({descricao})")

            if criticos:
                print("\nCRÍTICO (Ações altamente perigosas detectadas):")
                for critico in criticos:
                    print(critico)
                print("\nRECOMENDAÇÃO: NÃO CONFIE NESTE ARQUIVO! NÃO ATIVE AS MACROS!")
            else:
                print("\nO documento possui programação ativa, mas nenhum comportamento obviamente destrutivo foi identificado.")
        else:
            print("RESULTADO: Documento limpo. Nenhuma macro ou código ativo oculto foi encontrado.")

    except Exception as e:
        print(f"❌ Falha ao analisar as macros: {str(e)}")

def analisar_documento(caminho_arquivo):
    if not os.path.exists(caminho_arquivo):
        print(f"❌ Erro: O arquivo '{caminho_arquivo}' não foi encontrado.")
        return

    print("=" * 60)
    print(f"ANALISANDO ARQUIVO: {os.path.basename(caminho_arquivo)}")
    print("=" * 60)

    tipo = identificar_tipo_arquivo(caminho_arquivo)

    if tipo == 'PDF':
        analisar_pdf(caminho_arquivo)
    elif tipo == 'RTF':
        analisar_rtf(caminho_arquivo)
    elif tipo in ['OFFICE_ANTIGO', 'OFFICE_MODERNO']:
        analisar_office(caminho_arquivo, tipo)
    elif tipo == 'ZIP_COMUM':
        print("TIPO DETECTADO: Arquivo Compactado (ZIP)")
        print("👉 Extraia os arquivos antes de realizar a análise.")
    else:
        print("❓ TIPO DETECTADO: Formato não suportado ou Desconhecido")
        print("👉 Este script foi projetado para analisar PDFs, RTFs e documentos do Microsoft Office.")

    print("=" * 60)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso correto: python3 analisador_inteligente.py <caminho_do_arquivo>")
        sys.exit(1)

    analisar_documento(sys.argv[1])
