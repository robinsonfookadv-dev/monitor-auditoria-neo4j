# 🛡️ Graph-Audit: Monitor de Integridade e Cadeia de Custódia

Este projeto utiliza **Python** e o banco de dados de grafos **Neo4j** para garantir a integridade de ficheiros e o rastreio de responsabilidades em processos de perícia digital.

## 🚀 Funcionalidades
- **Geração de Hash (SHA-256):** Cria uma "impressão digital" única para cada ficheiro.
- **Rastreabilidade (Neo4j):** Mapeia a relação entre o Perito e o Ficheiro, garantindo a Cadeia de Custódia.
- **Imutabilidade Logística:** Registo de data, hora e autor da custódia.

## 🛠️ Tecnologias Utilizadas
- **Python 3.x**: Scripting e automação.
- **Neo4j (Cypher)**: Base de dados de grafos para linhagem de dados (*Data Lineage*).
- **Hashlib**: Para cálculos criptográficos de integridade.

## 📂 Como o Grafo é estruturado?
O sistema cria nós de `(:Perito)` e `(:Ficheiro)`, conectando-os através do relacionamento `[:RESPONSAVEL_POR]`. Isso permite visualizar rapidamente quem teve acesso a cada evidência digital.

---
*Projeto desenvolvido sob orientação de mentoria para aplicação em conformidade e LGPD.*
