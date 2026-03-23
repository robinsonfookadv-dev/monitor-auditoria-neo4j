# 🛡️ Sistema de Auditoria GRC & Compliance - Neo4j

Este projeto é uma ferramenta de **Governança, Risco e Conformidade** desenvolvida em Python para gestão de ativos e usuários em grafos.

## 🛠️ Tecnologias Utilizadas
- **Linguagem:** Python 3.12
- **Banco de Dados:** Neo4j (Graph Database) na Nuvem (Aura DB)
- **Segurança:** Bcrypt (Hash de Senhas) e SHA-256 (Integridade de Documentos)
- **Interface:** Rich (CLI moderna)

## 🔐 Diferenciais Técnicos
- **Forense:** Todos os relatórios PDF gerados possuem assinatura digital (Hash SHA-256) para garantir a imutabilidade em auditorias.
- **Segurança:** As credenciais são gerenciadas via variáveis de ambiente (.env).
- **Relacionamentos:** Mapeamento de acessos entre Colaboradores e Hosts usando teoria de grafos.

## 🚀 Como Executar
1. Clone o repositório.
2. Instale as dependências: `pip install -r requirements.txt`.
3. Configure o arquivo `.env` com suas chaves do Neo4j.
4. Execute: `python neo4j_nuvem.py`.
