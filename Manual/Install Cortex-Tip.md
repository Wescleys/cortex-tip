# 🛡️ Guia Oficial de Instalação — Cortex TIP

Guia definitivo de instalação e inicialização da plataforma **Cortex TIP** em ambientes Linux (Ubuntu 22.04 / 24.04 LTS / Debian 11 e 12).

Este procedimento foi consolidado considerando todas as proteções modernas do Linux (como PEP 668 no Python), permissões de socket Docker, versões do Docker Compose e tratamento de persistência de volumes.

---

## 💻 Requisitos do Sistema

- **Sistema Operacional**: Ubuntu 22.04 LTS, Ubuntu 24.04 LTS ou Debian 11/12
- **Hardware Recomendado**: 2+ vCPUs, 4 GB de RAM, 20 GB de disco
- **Portas de Rede**:
  - `80/TCP`: Interface Web do Cortex TIP
  - `3306/TCP`: Banco de Dados MariaDB 11.4 LTS (interno/opcional para acesso externo)
  - `11434/TCP`: Servidor Ollama (IA Local)

---

## 📋 Passo 1: Preparação do Sistema e Docker Compose V2

Instale o **Docker Engine** e o plugin oficial do **Docker Compose V2** (evita erros de incompatibilidade como `'ContainerConfig'` e `'name'` presentes no Compose legadão v1):

```bash
# 1. Atualize as listas de pacotes e o sistema
sudo apt update && sudo apt upgrade -y

# 2. Instale o Docker e o plugin Docker Compose V2 oficial do Ubuntu/Debian
sudo apt install -y docker.io docker-compose-v2 curl

# 3. Habilite e inicialize o serviço do Docker
sudo systemctl enable --now docker

# 4. Adicione o seu usuário ao grupo docker (evita erro de permissão no socket /var/run/docker.sock)
sudo usermod -aG docker $USER

# 5. Aplique a permissão imediatamente na sessão atual sem precisar reiniciar o terminal
newgrp docker
```

> **Verificação:**
> ```bash
> docker compose version
> ```
> O retorno deve indicar: `Docker Compose version v2.x.x`.

---

## 🐍 Passo 2: Instalação da CLI `cortex-tip` via PyPI

No Ubuntu 24.04 e distribuições recentes, o Python bloqueia instalações globais com `pip` puro (`error: externally-managed-environment` / PEP 668). A forma oficial e segura é utilizar o **`pipx`**:

```bash
# 1. Instale o gerenciador pipx
sudo apt install -y pipx

# 2. Registre as variáveis de ambiente e recarregue o terminal
pipx ensurepath
source ~/.bashrc

# 3. Instale a CLI cortex-tip do repositório oficial PyPI
pipx install cortex-tip
```

---

## 🧹 Passo 3: Limpeza Preventiva de Conflitos

Caso o servidor já tenha tido execuções anteriores ou contêineres temporários pausados, execute a limpeza preventiva:

```bash
docker rm -f cortex-app cortex-mariadb 2>/dev/null || true
docker network rm cortex-network 2>/dev/null || true
```

> 🔒 **Importante sobre os Dados:** 
> O comando acima encerra apenas processos/contêineres órfãos. Todos os dados das suas tabelas e históricos ficam salvos no volume persistente `cortex_mariadb_data` e **não são afetados**.

---

## 🚀 Passo 4: Inicialização da Plataforma

Com o ambiente pronto, execute um único comando:

```bash
cortex-tip
```

O comando irá:
1. Conectar-se ao Docker Hub e baixar a imagem oficial hardened: `wescleysilva/cortex-tip:latest`.
2. Inicializar o contêiner do **MariaDB 11.4 LTS** com volume persistente de dados (`cortex_mariadb_data`).
3. Aguardar o healthcheck do banco de dados passar para o estado saudável (`healthy`).
4. Iniciar a aplicação web do Cortex TIP na porta `80`.

Acesse no navegador:
👉 **`http://<IP-DO-SERVIDOR>:80`**

---

## 🧠 Passo 5: Configuração da IA Local (Ollama)

Para evitar gargalos de CPU e timeouts de 180s, o Cortex TIP é otimizado para o modelo leve de alta performance **Llama 3.2 3B**:

### 1. Baixe o modelo no servidor onde o Ollama roda:
```bash
ollama run llama3.2:3b
```

### 2. Ative no painel Web do Cortex TIP:
1. Acesse o painel: `http://<IP-DO-SERVIDOR>:80`
2. Navegue até **Configurações** (`/settings`) -> aba **Inteligência Artificial**.
3. Em **Provedor de IA**, escolha **Ollama Local**.
4. Defina a URL: `http://localhost:11434` (ou o IP correspondente da rede).
5. No seletor de modelos, selecione **`llama3.2:3b`** e clique em **Salvar Configurações**.

O modelo responderá às consultas de IOCs em **menos de 15 segundos**, trazendo veredito, resumo técnico, família de ameaça e comandos de mitigação.

---

## 🛠️ Comandos de Gestão da Plataforma

| Operação | Comando | Descrição |
| :--- | :--- | :--- |
| **Iniciar** | `cortex-tip` | Inicia MariaDB e aplicação web em segundo plano |
| **Atualizar** | `cortex-tip update` | Baixa a imagem mais recente do Docker Hub e recria a app sem tocar nos dados do banco |
| **Status** | `cortex-tip status` | Exibe a integridade dos contêineres e portas em uso |
| **Logs** | `cortex-tip logs` | Acompanha os logs da aplicação e eventos em tempo real (`Ctrl+C` para sair) |
| **Parar** | `cortex-tip stop` | Pausa os serviços com segurança, preservando os dados |
| **Apenas Banco** | `cortex-tip db:up` | Inicializa exclusivamente o contêiner do MariaDB 11.4 na porta `3306` |
| **Ajuda** | `cortex-tip help` | Lista os comandos e opções disponíveis |
