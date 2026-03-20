import os
import re
import platform
import bcrypt
import hashlib
import sys
from datetime import datetime
from dotenv import load_dotenv
from neo4j import GraphDatabase
from fpdf import FPDF
from fpdf.enums import XPos, YPos
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich import print as rprint
from rich.text import Text
from rich.align import Align

# --- CONFIGURAÇÃO INICIAL ---
load_dotenv()
console = Console()

def limpar_tela():
    if platform.system() == "Windows": os.system('cls')
    else: os.system('clear')

def exibir_cabecalho():
    titulo = Text("SISTEMA GRC - AUDITORIA DE ATIVOS", style="bold white on blue", justify="center")
    rprint(Panel(titulo, subtitle="v33.0 - Final Edition (Bcrypt + SHA-256 + Search)", border_style="bright_blue"))

def formatar_cpf(valor):
    numeros = re.sub(r'\D', '', str(valor))
    if len(numeros) != 11: return None
    return f"{numeros[:3]}.{numeros[3:6]}.{numeros[6:9]}-{numeros[9:]}"

def formatar_data(valor):
    numeros = re.sub(r'\D', '', str(valor))
    if len(numeros) != 8: return valor
    return f"{numeros[:2]}/{numeros[2:4]}/{numeros[4:]}"

# --- CLASSE DO SISTEMA ---
class AppCiberLGPD:
    def __init__(self):
        uri = os.getenv("NEO4J_URI")
        user = os.getenv("NEO4J_USER")
        pw = os.getenv("NEO4J_PASSWORD")
        if not all([uri, user, pw]):
            raise Exception("Arquivo .env ausente ou incompleto!")
        self.driver = GraphDatabase.driver(uri, auth=(user, pw))
        self.usuario_logado = None

    def login(self):
        limpar_tela(); exibir_cabecalho()
        rprint(Align.center(Panel("🔒 [bold yellow]LOGIN DO ADMINISTRADOR[/bold yellow]", border_style="yellow", width=50)))
        u = Prompt.ask("[cyan]Usuário[/cyan]"); p = Prompt.ask("[cyan]Senha[/cyan]", password=True)
        try:
            with self.driver.session() as session:
                res = session.run("MATCH (a:Admin {username: $u}) RETURN a.password as h, a.name as n", u=u).single()
                if res and bcrypt.checkpw(p.encode('utf-8'), res['h'].encode('utf-8')):
                    self.usuario_logado = u; return True
        except: pass
        if u == os.getenv("ADMIN_USER") and p == os.getenv("ADMIN_PASS"):
            self.usuario_logado = u; return True
        return False

    def vincular_usuario(self, nome, cpf, host, cargo, data_adm):
        with self.driver.session() as session:
            session.run("MERGE (h:Host {hostname: $h})", h=host)
            query = """
            MERGE (u:User {cpf: $cpf}) SET u.name=$nome, u.role=$cargo, u.status='Ativo', u.admitido_em=$data 
            WITH u MATCH (h:Host {hostname: $host}) MERGE (u)-[:ACCESSES]->(h)
            """
            session.run(query, nome=nome, cpf=cpf, host=host, cargo=cargo, data=data_adm)
            rprint("[bold green]✅ Usuário cadastrado e vinculado![/bold green]")

    def buscar_por_nome(self, nome):
        with self.driver.session() as session:
            query = "MATCH (u:User) WHERE u.name =~ $regex RETURN u.name as nome, u.cpf as cpf, u.status as status"
            return list(session.run(query, regex=f"(?i).*{nome}.*"))

    def buscar_por_cpf(self, cpf):
        with self.driver.session() as session:
            res = session.run("MATCH (u:User {cpf: $cpf}) OPTIONAL MATCH (u)-[:ACCESSES]->(h:Host) RETURN u, collect(h.hostname) as hosts", cpf=cpf).single()
            if res:
                u = res['u']
                table = Table(title=f"🔍 FICHA: {u['name']}", border_style="bright_blue")
                table.add_column("DADO"); table.add_column("VALOR")
                table.add_row("STATUS", str(u.get('status', '---')))
                table.add_row("CPF", str(u.get('cpf', '---')))
                table.add_row("CARGO", str(u.get('role', '---')))
                table.add_row("HOSTS", ", ".join(res['hosts']))
                rprint(table); return res['u']['cpf']
            return None

    def demitir_usuario(self, cpf, data_dem):
        with self.driver.session() as session:
            session.run("MATCH (u:User {cpf: $cpf}) SET u.status = 'Inativo', u.demitido_em = $data", cpf=cpf, data=data_dem)
            rprint(Panel(f"[bold white on red] ⚠ STATUS ALTERADO PARA INATIVO [/]\nCPF: {cpf}\nData: {data_dem}", border_style="red"))

    def gerenciar_hosts(self, acao, hostname):
        with self.driver.session() as session:
            if acao == "criar": session.run("MERGE (h:Host {hostname: $n})", n=hostname)
            else: session.run("MATCH (h:Host {hostname: $n}) DETACH DELETE h", n=hostname)
            rprint(f"[green]Host {hostname} processado.[/green]")

    def gerar_relatorio_pdf(self):
        pdf = FPDF(); pdf.add_page(); pdf.set_font("Helvetica", 'B', 16)
        pdf.cell(190, 10, "RELATÓRIO DE AUDITORIA GRC", align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(10)
        with self.driver.session() as session:
            results = session.run("MATCH (u:User) OPTIONAL MATCH (u)-[:ACCESSES]->(h:Host) RETURN u, collect(h.hostname) as hosts ORDER BY u.name")
            pdf.set_fill_color(230, 230, 230); pdf.set_font("Helvetica", 'B', 10)
            pdf.cell(65, 8, "Nome", 1, fill=True); pdf.cell(40, 8, "CPF", 1, fill=True)
            pdf.cell(30, 8, "Status", 1, fill=True); pdf.cell(55, 8, "Hosts", 1, fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("Helvetica", '', 9)
            for r in results:
                st = str(r['u'].get('status', 'Ativo'))
                pdf.set_text_color(0, 51, 153) if st == "Ativo" else pdf.set_text_color(200, 0, 0)
                pdf.cell(65, 8, str(r['u']['name'])[:30], 1); pdf.cell(40, 8, str(r['u']['cpf']), 1)
                pdf.cell(30, 8, st, 1, align='C'); pdf.set_text_color(0, 0, 0)
                pdf.cell(55, 8, ", ".join(r['hosts'])[:25], 1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        nome_pdf = f"Relatorio_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
        pdf.output(nome_pdf)
        
        # --- CÁLCULO SHA-256 (INTEGRIDADE FORENSE) ---
        with open(nome_pdf, "rb") as f:
            hash_sha = hashlib.sha256(f.read()).hexdigest()
        
        rprint(Panel(f"[bold green]✅ PDF GERADO COM SUCESSO![/]\n[cyan]Arquivo:[/] {nome_pdf}\n[yellow]SHA-256:[/] {hash_sha}", border_style="green", title="Assinatura Digital"))

# --- MENU PRINCIPAL ---
def main():
    try:
        app = AppCiberLGPD()
        if not app.login(): rprint("[red]Falha no Login![/red]"); return
        
        while True:
            limpar_tela(); exibir_cabecalho()
            rprint(Panel("[1] Cadastrar | [2] Buscar | [3] Demitir | [4] PDF | [5] Hosts | [0] Sair", border_style="bright_blue"))
            op = Prompt.ask("Opção", choices=["1", "2", "3", "4", "5", "0"])

            if op == "0": break
            
            elif op == "1":
                n = Prompt.ask("Nome"); raw_c = Prompt.ask("CPF (11 num)"); c = formatar_cpf(raw_c)
                if c: app.vincular_usuario(n, c, Prompt.ask("Host"), Prompt.ask("Cargo"), formatar_data(Prompt.ask("Data Adm")))
                else: rprint("[red]CPF Inválido![/red]")
                Prompt.ask("\n[Enter] para voltar")

            elif op == "2":
                busca = Prompt.ask("Nome ou CPF")
                if busca.isdigit() and len(busca) == 11: app.buscar_por_cpf(formatar_cpf(busca))
                else:
                    lista = app.buscar_por_nome(busca)
                    if not lista: rprint("[red]Nenhum resultado.[/red]")
                    else:
                        for i, r in enumerate(lista): rprint(f"[{i}] {r['nome']} ({r['status']})")
                        idx = Prompt.ask("Escolha o número ou [Enter] para sair", default="")
                        if idx: app.buscar_por_cpf(lista[int(idx)]['cpf'])
                Prompt.ask("\n[Enter] para voltar")

            elif op == "3":
                rprint("[yellow]--- MÓDULO DE DESLIGAMENTO (GRC) ---[/yellow]")
                busca = Prompt.ask("Informe o Nome ou CPF do colaborador")
                cpf_alvo = None
                
                if busca.isdigit() and len(busca) == 11:
                    cpf_alvo = formatar_cpf(busca)
                else:
                    lista = app.buscar_por_nome(busca)
                    if lista:
                        for i, r in enumerate(lista): rprint(f"[{i}] {r['nome']} - CPF: {r['cpf']}")
                        idx = Prompt.ask("Escolha o número do colaborador para DEMITIR")
                        cpf_alvo = lista[int(idx)]['cpf']
                
                if cpf_alvo:
                    data_d = formatar_data(Prompt.ask("Data de Demissão (DDMMAAAA)"))
                    if Prompt.ask(f"Confirma demissão do CPF {cpf_alvo}?", choices=["s", "n"]) == "s":
                        app.demitir_usuario(cpf_alvo, data_d)
                else: rprint("[red]Colaborador não localizado.[/red]")
                Prompt.ask("\n[Enter] para voltar")

            elif op == "4": app.gerar_relatorio_pdf(); Prompt.ask("\n[Enter] para voltar")
            
            elif op == "5":
                sub = Prompt.ask("[1] Adicionar Host [2] Remover Host", choices=["1","2"])
                app.gerenciar_hosts("criar" if sub=="1" else "excluir", Prompt.ask("Hostname"))
                Prompt.ask("\n[Enter] para voltar")

    except Exception as e:
        rprint(Panel(f"[bold red]ERRO CRÍTICO:[/bold red] {e}", border_style="red"))
        input("\nPressione ENTER para fechar o programa...")

if __name__ == "__main__":
    main()
