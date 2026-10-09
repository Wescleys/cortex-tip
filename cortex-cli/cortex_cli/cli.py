#!/usr/bin/env python3
"""
Cortex TIP CLI — Threat Intelligence Platform & SOC Platform
Entry point for managing the Cortex TIP Docker stack.
"""

import sys
import os
import shutil
import subprocess
from pathlib import Path

# Suporte universal a UTF-8 (evita UnicodeEncodeError no Windows cp1252)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

VERSION = "2.2.0"

BANNER = r"""
=============================================================
   🛡️  CORTEX TIP - Threat Intelligence & SOC Platform
   🐳  Docker Stack Manager (MariaDB 11.4 + Protected App)
=============================================================
"""

def print_banner():
    print(BANNER)

def check_docker():
    """Verifica se o Docker está instalado e se o daemon está respondendo."""
    docker_bin = shutil.which("docker")
    if not docker_bin:
        print("❌ Erro: O Docker não está instalado ou não foi encontrado no PATH.", file=sys.stderr)
        print("👉 Instale o Docker Desktop / Docker Engine: https://docs.docker.com/get-docker/\n", file=sys.stderr)
        sys.exit(1)

    try:
        subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("⚠️  Atenção: O Docker Engine não está rodando ou seu usuário não tem permissão.", file=sys.stderr)
        if sys.platform.startswith("linux"):
            print("👉 No Linux, execute os comandos abaixo para conceder permissão ao seu usuário:", file=sys.stderr)
            print("   sudo usermod -aG docker $USER", file=sys.stderr)
            print("   newgrp docker", file=sys.stderr)
            print("   sudo systemctl start docker\n", file=sys.stderr)
        else:
            print("👉 Certifique-se de que o Docker Desktop está aberto e inicializado.\n", file=sys.stderr)
        sys.exit(1)

def get_compose_cmd():
    """Detecta se o Docker Compose V2 (plugin) ou V1 (legado) está instalado."""
    # Testa primeiro Docker Compose V2 (docker compose)
    try:
        res = subprocess.run(["docker", "compose", "version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if res.returncode == 0:
            return ["docker", "compose"]
    except Exception:
        pass

    # Testa Docker Compose V1 (docker-compose)
    compose_bin = shutil.which("docker-compose")
    if compose_bin:
        print("⚠️  Aviso: Você está usando o docker-compose V1 (legado).", file=sys.stderr)
        print("👉 Recomendado instalar o Compose V2 moderno: sudo apt install -y docker-compose-plugin\n", file=sys.stderr)
        return ["docker-compose"]

    print("❌ Erro: O Docker Compose não está instalado.", file=sys.stderr)
    print("👉 No Linux Ubuntu/Debian, instale com:", file=sys.stderr)
    print("   sudo apt update && sudo apt install -y docker-compose-plugin\n", file=sys.stderr)
    sys.exit(1)

def get_compose_file():
    """Obtém o caminho do docker-compose.yml local ou usa o embutido no pacote."""
    cwd_compose = Path.cwd() / "docker-compose.yml"
    if cwd_compose.is_file():
        return cwd_compose

    pkg_compose = Path(__file__).resolve().parent / "docker-compose.yml"
    if pkg_compose.is_file():
        return pkg_compose

    # Fallback caso esteja rodando do repositório
    repo_compose = Path(__file__).resolve().parents[1] / "docker-compose.yml"
    if repo_compose.is_file():
        return repo_compose

    print("❌ Erro: docker-compose.yml não foi encontrado.", file=sys.stderr)
    sys.exit(1)

def run_compose(compose_cmd, compose_file, extra_args):
    """Executa um comando docker compose garantindo o isolamento do projeto 'cortex'."""
    cmd = compose_cmd + ["-p", "cortex", "-f", str(compose_file)] + extra_args
    try:
        return subprocess.run(cmd, cwd=str(compose_file.parent)).returncode
    except KeyboardInterrupt:
        print("\nOperação interrompida pelo usuário.")
        return 0

def show_help():
    print("""
Uso: cortex-tip [COMANDO]

Comandos disponíveis:
  cortex-tip [start|up]    Inicia a stack completa (MariaDB 11.4 + Web App)
  cortex-tip stop|down     Pausa os contêineres mantendo os dados salvos
  cortex-tip status|ps     Exibe o status e integridade dos serviços
  cortex-tip logs          Acompanha os logs da aplicação em tempo real
  cortex-tip update|pull   Atualiza para a versão mais recente do Docker Hub
  cortex-tip db:up         Inicia exclusivamente o contêiner do MariaDB
  cortex-tip version       Exibe a versão instalada da CLI
  cortex-tip help          Exibe esta mensagem de ajuda
""")

def main():
    args = sys.argv[1:]
    command = args[0] if args else "start"

    if command in ("--version", "-v", "version"):
        print(f"cortex-tip CLI v{VERSION}")
        sys.exit(0)

    if command in ("--help", "-h", "help"):
        print_banner()
        show_help()
        sys.exit(0)

    print_banner()
    check_docker()
    compose_cmd = get_compose_cmd()
    compose_file = get_compose_file()

    if command in ("start", "up"):
        print("🚀 Iniciando a plataforma Cortex TIP completa em Docker...")
        print("⏳ Inicializando banco MariaDB 11.4 e aplicação protegida...\n")
        code = run_compose(compose_cmd, compose_file, ["up", "-d"])
        if code == 0:
            print("\n✅ Plataforma Cortex TIP em execução com sucesso!")
            print("-------------------------------------------------------------")
            print("🐘 Banco de Dados:  cortex-mariadb (MariaDB 11.4 LTS)")
            print("⚡ Aplicação Web:   cortex-app (Hardened & Compilada)")
            print("🌐 Painel de Acesso: http://localhost:80")
            print("💾 Volume de Dados: cortex_mariadb_data (Persistente)")
            print("-------------------------------------------------------------\n")
        else:
            print(f"\n❌ Falha ao iniciar (código de saída: {code})", file=sys.stderr)
            sys.exit(code)

    elif command in ("stop", "down"):
        print("🛑 Parando a plataforma Cortex TIP...")
        code = run_compose(compose_cmd, compose_file, ["stop"])
        if code == 0:
            print("\n✅ Serviços pausados com segurança. Dados preservados nos volumes.")
        sys.exit(code)

    elif command in ("status", "ps"):
        print("📊 Status dos contêineres Cortex TIP:\n")
        code = run_compose(compose_cmd, compose_file, ["ps"])
        sys.exit(code)

    elif command == "logs":
        print("📜 Visualizando logs da plataforma (Pressione Ctrl+C para sair)...\n")
        code = run_compose(compose_cmd, compose_file, ["logs", "-f"])
        sys.exit(code)

    elif command in ("update", "pull"):
        print("🔄 Atualizando imagens do Cortex TIP a partir do Docker Hub...")
        code = run_compose(compose_cmd, compose_file, ["pull"])
        if code == 0:
            print("♻️ Reiniciando contêineres com a nova versão...")
            code = run_compose(compose_cmd, compose_file, ["up", "-d"])
            print("\n✅ Cortex TIP atualizado para a versão mais recente!")
        sys.exit(code)

    elif command == "db:up":
        print("🚀 Subindo apenas o contêiner do MariaDB 11.4...")
        code = run_compose(compose_cmd, compose_file, ["up", "-d", "cortex-mariadb"])
        if code == 0:
            print("\n✅ Contêiner MariaDB ativo em 127.0.0.1:3306!")
        sys.exit(code)

    else:
        print(f"❌ Comando desconhecido: '{command}'\n", file=sys.stderr)
        show_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
