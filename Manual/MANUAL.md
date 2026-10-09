<p align="center">
  <img src="static/cortex.png" alt="Cortex TIP Logo" width="160">
</p>

# Manual de Operação e Administração - Cortex TIP (Threat Intelligence Platform)

---

## 1. Visão Geral da Plataforma

O **Cortex TIP** é uma plataforma moderna e centralizada de **Threat Intelligence (TI)** e apoio a operações de **SOC (Security Operations Center)**. Ele conecta bases de inteligência contra ameaças existentes (como instâncias do **MISP**), executa enriquecimento multi-fonte em tempo real (VirusTotal, AbuseIPDB, Geolocalização, MITRE ATT&CK) e emprega **Inteligência Artificial Generativa Local (Ollama) ou em Nuvem** para atuar como um copiloto de análise investigativa, sugerindo vereditos e comandos imediatos de contenção e mitigação para Firewalls e EDRs.

### Principais Capacidades:
- **Gestão Híbrida de MISP:** Sincronização em alta performance via leitura direta do MySQL e ingestão oficial de eventos e atributos via PyMISP.
- **Enriquecimento Multi-Origem:** Cruzamento instantâneo com bases reputacionais (VirusTotal v3, AbuseIPDB v2, MaxMind/IP-API, MITRE ATT&CK Matrix).
- **Analista SOC com IA Local (Ollama):** Avaliação de risco, sumário executivo, visualização do raciocínio analítico (*Chain-of-Thought*) e comandos prontos para mitigação de ameaças.
- **Grafo de Correlação Interativo:** Conexão visual dinâmica entre IOCs, eventos do MISP, infraestrutura de rede e táticas do MITRE.
- **Controle de Acesso Baseado em Funções (RBAC):** Perfis de *Administrador*, *Analista* e *Visualizador* com trilha de auditoria completa.
- **Exportação Automática de Listas:** Endpoints JSON para consumo por firewalls corporativos, proxies, EDRs e SIEMs.

---

## 2. Arquitetura de Componentes

```
                              ┌────────────────────────┐
                              │  Navegador do Analista │
                              └───────────┬────────────┘
                                          │ HTTP / HTTPS (CSRF + HttpOnly)
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                             CORTEX TIP SERVER                               │
│                                                                             │
│  ┌───────────────────────┐  ┌───────────────────────┐  ┌─────────────────┐ │
│  │   cortex.py (Flask)   │  │   auth.py (RBAC/CSRF) │  │  db_system.py   │ │
│  └───────────┬───────────┘  └───────────────────────┘  └────────┬────────┘ │
│              │                                                  │           │
│              │                                                  ▼           │
│              │                                       ┌────────────────────┐ │
│              │                                       │  cortex_system.db  │ │
│              │                                       │  (SQLite Local)    │ │
│              │                                       └────────────────────┘ │
├──────────────┼──────────────────────────────┬───────────────────────────────┤
│              ▼                              ▼                               │
│  ┌───────────────────────┐      ┌───────────────────────┐                   │
│  │    misp_service.py    │      │ enrichment_service.py │                   │
│  └───────┬───────────────┘      └───────────┬───────────┘                   │
│          │                                  │                               │
│          │ PyMISP / MySQL Direct            │ REST APIs                     │
└──────────┼──────────────────────────────────┼───────────────────────────────┘
           ▼                                  ▼
┌──────────────────────┐          ┌───────────────────────┐
│   Instância MISP     │          │ Bases de Inteligência │
│  - REST API (5000)   │          │  - VirusTotal v3      │
│  - MySQL DB (3306)   │          │  - AbuseIPDB v2       │
└──────────────────────┘          │  - GeoIP / ASN        │
                                  └───────────────────────┘
                                              ▲
                                              │ Ollama API (11434)
                                  ┌───────────┴───────────┐
                                  │   Servidor de IA      │
                                  │  - deepseek-r1:8b     │
                                  │  - qwen2.5-coder:7b   │
                                  └───────────────────────┘
```

---

## 3. Requisitos e Instalação

### Requisitos Mínimos:
- **Sistema Operacional:** Linux (Ubuntu 22.04 LTS / Debian 12 / Rocky Linux 9) ou Windows 10/11 / Windows Server 2019+.
- **Python:** Versão 3.10 ou superior (testado e homologado em Python 3.13).
- **Memória RAM:** 
  - Mínimo de **4 GB** (se o servidor Ollama rodar em máquina separada).
  - Recomendado **16 GB a 32 GB** com GPU dedicada se rodar LLMs locais (DeepSeek R1, Qwen) no mesmo host.
- **Rede:** Acesso de rede à instância do MISP (portas 443/5000 e 3306) e saída HTTPS para VirusTotal/AbuseIPDB.

### Dependências Python:
As bibliotecas obrigatórias para o funcionamento do sistema são:
```bash
pip install flask requests pymisp mysql-connector-python
```

### Inicialização do Servidor:
Para iniciar o Cortex TIP em ambiente de produção/operação:
```bash
# Execução direta:
python cortex.py

# Ou em background no Linux:
nohup python3 cortex.py > logs/cortex.out 2>&1 &
```
*O servidor escutará na interface `0.0.0.0` na porta `80` (ou na porta configurada).*

---

## 4. Primeiro Acesso & Provisionamento Inicial (`/setup`)

O Cortex TIP possui o conceito de **Setup Automatizado estilo Portainer**:

1. Ao subir o sistema pela primeira vez com o banco de dados limpo, qualquer requisição web redireciona automaticamente para a rota:
   ```
   http://<IP_DO_SERVIDOR>/setup
   ```
2. **Criação do Super Administrador:**
   - **Nome e Sobrenome:** Identificação do responsável principal da plataforma.
   - **E-mail:** Será a credencial de login corporativa de nível administrativo.
   - **Senha Mestra:** Deve atender estritamente à política de senhas fortes:
     - Mínimo de **12 caracteres**.
     - Pelo menos uma **letra maiúscula** (`A-Z`).
     - Pelo menos uma **letra minúscula** (`a-z`).
     - Pelo menos um **número** (`0-9`).
     - Pelo menos um **caractere especial** (`!@#$%^&*...`).
3. Ao concluir o envio, a conta mestre é gravada e o login ocorre automaticamente. A rota `/setup` é permanentemente bloqueada para novos acessos.

---

## 5. Gestão de Identidades e Controle de Acesso (RBAC)

O Cortex adota o modelo **Role-Based Access Control** com três perfis bem delimitados:

| Perfil | Nível | Permissões e Acessos |
| :--- | :---: | :--- |
| **Administrador (`admin`)** | Total | Acesso irrestrito. Gerencia usuários, altera configurações do sistema/APIs, cadastra IOCs, consulta auditoria e executa todas as ações operacionais. |
| **Analista (`analista`)** | Operacional | Consulta o dashboard, realiza buscas avançadas, aciona o enriquecimento e o Analista IA, cadastra novos IOCs no MISP e consulta a trilha de auditoria. Não pode alterar configurações de infraestrutura nem editar outros usuários. |
| **Visualizador (`visualizador`)** | Consulta | Acesso de somente leitura. Pode visualizar o Dashboard, mapas, notícias de cibersegurança e listas de integração pública. |

### Gerenciamento de Usuários (`/users`):
Acessível exclusivamente pelo Administrador na barra de navegação:
- **Cadastrar Usuário:** Abre a janela modal com preenchimento de nome, e-mail, cargo e senha inicial temporária.
- **Editar Usuário:** Permite alterar dados, cargo (*Admin/Analista/Visualizador*), ativar/bloquear conta e redefinir senha.
- **Desativar Acesso:** Suspende a conta imediatamente sem excluir o histórico de auditoria associado ao operador.
- **Excluir Usuário:** Remove o usuário do banco de dados. 
  > **Trava de Segurança:** O sistema impede a exclusão da própria conta do administrador logado e proíbe a remoção do último administrador ativo da plataforma.

### Área de Perfil do Usuário (`/profile`):
Qualquer operador autenticado pode gerenciar seus próprios dados clicando no avatar superior direito:
- Atualização de nome e e-mail.
- Troca de senha com validação mandatória da senha atual para evitar sequestro de sessão.

---

## 6. Painel de Configurações Administrativas (`/settings`)

A tela de configurações permite integrar o Cortex à infraestrutura corporativa:

### 1. Integração com o MISP
- **Modo Híbrido de Leitura:**
  - **Banco de Dados MySQL:** Recomendado para ambientes com dezenas de milhares de IOCs. Realiza consultas indexadas de altíssima velocidade diretamente nas tabelas `attributes` e `events`.
  - **API REST Oficial do MISP:** Utiliza a API REST e PyMISP para sincronização.
- **Credenciais da API:** URL do MISP (`https://misp.local`), Chave de Autenticação (*Auth Key*) e alternador de validação SSL (*Verify SSL*).
- **Credenciais do Banco MySQL:** Host/IP, Porta (padrão `3306`), Usuário, Senha e Nome do Banco de Dados (`misp`).
- **Botões de Teste em Tempo Real:**
  - `Testar Conexão com API`: Envia um ping para a API do MISP e valida a autenticidade da chave.
  - `Testar Conexão com MySQL`: Abre conexão de teste e afere a contagem de registros na base.

### 2. Inteligência Artificial (Analista Virtual SOC)
- **Provedor Primário:** Suporte a **Ollama Local** (padrão soberano sem envio de dados para terceiros), **Google Gemini**, **OpenAI** ou **Anthropic**.
- **Servidor Ollama:** URL do serviço (ex: `http://localhost:11434` ou IP interno).
- **Auto-Detecção de Modelos:** Botão interativo que consulta os modelos LLM instalados na máquina e preenche a lista automaticamente (modelos testados: `deepseek-r1:8b`, `deepseek-r1:1.5b`, `qwen2.5-coder:7b`, `llama3`).
- **Chaves de Nuvem (Opcionais):** Campos para chaves de API caso opte por usar Gemini, GPT-4o ou Claude.

### 3. Fontes de Enriquecimento Externo
- **VirusTotal (v3 API):** Chave de API para consultas automatizadas de hash, reputação de IPs e URLs.
- **AbuseIPDB (v2 API):** Chave de API para obtenção do *Abuse Confidence Score* e relatórios de denúncias da comunidade.

---

## 7. Operação Diária do Analista SOC

### A. Dashboard Executivo (`/`)
- **Contadores de Ameaças:** Exibição do total consolidado de IOCs ativos, IPs maliciosos, Domínios e Hashes.
- **Mapa Mundi de Ameaças:** Mapa interativo em tema escuro com círculos proporcionais destacando a concentração geográfica dos nós de ataque.
- **Cyber News Feed (Últimas 24h):** Monitoramento contínuo em tempo real dos feeds do *The Hacker News* e *BleepingComputer*.
- **Vulnerabilidades Críticas (CISA KEV):** Feed oficial de falhas ativamente exploradas (*Known Exploited Vulnerabilities*) para priorização de patching.

### B. Busca, Enriquecimento e Investigação de IOCs (`/search`)
1. Insira no campo de busca qualquer indicador: **Endereço IP** (`185.220.101.5`), **Domínio** (`malicious-domain.com`), **URL** ou **Hash** (`MD5`, `SHA1`, `SHA256`).
2. O sistema realiza busca instantânea na base local do MISP e oferece o botão **"Enriquecer com Inteligência"**:
   - **VirusTotal:** Taxa de detecção (ex: *15/70 Malicioso*), reputação e tags da comunidade.
   - **AbuseIPDB:** Score de abuso percentual, total de denúncias recentes e ISP/Domínio reverso.
   - **Geolocalização & ASN:** Mini-mapa Leaflet com coordenadas exatas, cidade, código do ASN e bandeira do país.
   - **Mapeamento MITRE ATT&CK:** Identificação das táticas associadas (ex: `T1071 - Command and Control`).
   - **Grafo de Correlação Visual:** Alterne entre a exibição tabular e o modo **Grafo**. O grafo interativo conecta visualmente o IOC aos eventos MISP correlacionados e aos atributos compartilhados na infraestrutura de ataque.
3. **Analista SOC com IA (Ollama):**
   - Veredito claro: **BENIGNO**, **SUSPEITO** ou **ALTAMENTE MALICIOSO**.
   - Resumo detalhado da ameaça em formato executivo.
   - Bloco colapsável com o raciocínio profundo da IA (*Chain-of-Thought* do DeepSeek-R1).
   - **Ações Imediatas de Contenção:** Comandos de firewall prontos para cópia rápida:
     - `iptables -A INPUT -s <IP> -j DROP`
     - Regras de EDR / PowerShell para bloqueio perimetral.

### C. Ingestão de IOCs no MISP com Rastreabilidade (`/add-ioc`)
1. Acesse o menu **"Adicionar IOC"**.
2. Preencha os atributos seguindo o padrão oficial do MISP:
   - **Categoria:** *Network activity*, *Payload delivery*, *Antivirus detection*, etc.
   - **Tipo do Indicador:** Seletor dinâmico que filtra tipos compatíveis com a categoria (*ip-dst*, *domain*, *url*, *md5*, *sha256*).
   - **Distribuição:** Nível de compartilhamento (*This community only*, *All communities*, *Inherit event*).
   - **Valor:** Suporta inserção de múltiplos valores (um por linha) para cadastro em massa.
   - **Comentário de Contexto:** Notas técnicas sobre o incidente ou chamado associado.
3. Ao submeter, o Cortex cria o evento oficial no MISP via `PyMISP` e registra o operador na trilha de auditoria.

### D. Trilha de Auditoria (`/audit`)
Relatório imutável que registra todas as operações de cadastro de indicadores realizadas pelos analistas:
- Nome e e-mail do operador.
- Cargo (*Admin* ou *Analista*).
- Indicador cadastrado e categoria.
- ID do evento criado no MISP e carimbo de data/hora oficial.

---

## 8. Integração Externa para Firewalls e SIEMs

O Cortex TIP disponibiliza feeds públicos limpos em formato JSON para ingestão automatizada por firewalls de borda (Fortinet, pfSense, Palo Alto), proxies e SIEMs:

| Endpoint | Conteúdo | Aplicação Típica |
| :--- | :--- | :--- |
| `GET /misp_ips.json` | Lista pura de IPs maliciosos sincronizados | Bloqueio dinâmico em Firewall (pfSense/IPSet) |
| `GET /misp_domains.json` | Lista de domínios maliciosos | Bloqueio via Pi-hole, AdGuard ou DNS RPZ |
| `GET /misp_urls.json` | Lista de URLs maliciosas | Bloqueio em Web Application Firewalls (WAF) |
| `GET /misp_hashes.json` | Hashes maliciosos (MD5/SHA256) | Blacklists de EDR e Antivírus corporativo |

---

## 9. Práticas de Segurança e Hardening Aplicadas

O Cortex TIP foi submetido a rigorosa auditoria técnica de segurança, incorporando as seguintes proteções ativas:

1. **Modo de Produção:** O interactive debugger do Werkzeug permanece estritamente desativado (`debug=False`).
2. **Defesa Anti-CSRF Global:** Padrão *Synchronizer Token Pattern* com tokens criptográficos imprevisíveis (`secrets.token_hex(32)`) validados via `hmac.compare_digest`.
3. **Cookies de Sessão Seguros:** Configurados com flags `HttpOnly` (prevenção de roubo via XSS) e `SameSite=Lax` (prevenção de envio em links cruzados).
4. **Higienização DOM contra XSS:** Neutralização de entidades HTML via `escapeHtml()` para dados externos de feeds e sanitização de Markdown via biblioteca `DOMPurify`.
5. **Mitigação de SSRF:** Validação estrita de esquema (`http/https`) e bloqueio de alcance a serviços de metadados de nuvem (`169.254.169.254`).
6. **Política de Senhas Fortes:** Exigência obrigatória de 12 caracteres com complexidade de classes de caracteres no cadastro e troca de senhas.
7. **Proteção do Repositório (`.gitignore`):** Isolamento total de arquivos `.db`, pastas de `logs/`, caches e segredos contra vazamentos acidentais em commits.

---

## 10. Procedimentos de Backup e Migração

### O que Fazer Backup:
Para preservar 100% das credenciais, usuários cadastrados, chaves de API e logs de auditoria, basta fazer o backup de um único arquivo:
- **`cortex_system.db`** (Banco SQLite local).

### Como Restaurar ou Migrar de Servidor:
1. Instale o Python 3.10+ no novo host.
2. Instale as dependências: `pip install flask requests pymisp mysql-connector-python`.
3. Copie a pasta da aplicação (`templates/`, `static/`, arquivos `.py`).
4. Cole o arquivo `cortex_system.db` salvo na raiz do projeto.
5. Inicie com `python cortex.py`. Todos os usuários, integrações e dados estarão prontos para uso imediatamente.
