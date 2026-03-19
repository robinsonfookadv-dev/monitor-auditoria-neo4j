import hashlib
import os
from datetime import datetime
from neo4j import GraphDatabase

# 1. FUNÇÃO PARA GERAR O HASH (A Digital do Arquivo)
def gerar_hash_sha256(caminho_arquivo):
    """Lê o arquivo e gera um hash SHA-256 para garantir a integridade."""
    sha256_hash = hashlib.sha256()
    try:
        with open(caminho_arquivo, "rb") as f:
            # Lê em blocos para não sobrecarregar a memória
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        return None

# 2. CLASSE PARA CONEXÃO COM O NEO4J (O Grafo)
class AuditoriaDigital:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def registrar_custodia(self, perito, arquivo, hash_val):
        """Cria o nó do perito e do arquivo, ligando-os no grafo."""
        with self.driver.session() as session:
            query = """
            MERGE (p:Perito {nome: $perito})
            CREATE (a:Arquivo {
                nome: $arquivo, 
                hash: $hash, 
                data_registro: $data,
                status: 'Integridade Verificada'
            })
            CREATE (p)-[:RESPONSAVEL_POR {tipo: 'Cadeia de Custódia'}]->(a)
            RETURN a.nome as arquivo_salvo
            """
            result = session.run(query, perito=perito, arquivo=arquivo, 
                                 hash=hash_val, data=datetime.now().isoformat())
            return result.single()

# --- EXECUÇÃO PRÁTICA ---
if __name__ == "__main__":
    # CONFIGURAÇÕES (Troque pela sua senha do Neo4j Desktop)
    URI = "bolt://localhost:7687"
    USER = "neo4j"
    PASSWORD = "SUA_SENHA_AQUI" 

    # NOME DO ARQUIVO PARA TESTE (Crie um arquivo chamado 'evidencia.txt' na mesma pasta)
    ARQUIVO_TESTE = "evidencia.txt"
    NOME_PERITO = "Robinson Shiam"

    # Passo 1: Gerar o Hash
    print(f"🔍 Analisando arquivo: {ARQUIVO_TESTE}...")
    hash_resultado = gerar_hash_sha256(ARQUIVO_TESTE)

    if hash_resultado:
        print(f"✅ Hash SHA-256 gerado: {hash_resultado}")

        # Passo 2: Salvar no Neo4j
        try:
            app = AuditoriaDigital(URI, USER, PASSWORD)
            app.registrar_custodia(NOME_PERITO, ARQUIVO_TESTE, hash_resultado)
            app.close()
            print("🌐 Dados registrados no Neo4j com sucesso!")
        except Exception as e:
            print(f"❌ Erro ao conectar no Neo4j: {e}")
    else:
        print("❌ Arquivo não encontrado para gerar o hash.")
