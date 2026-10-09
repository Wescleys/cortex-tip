import requests
import json
import logging
import re
import db_system

logger = logging.getLogger("ai_service")

THREAT_INTEL_SYSTEM_PROMPT = """Você é um Analista Sênior de Cyber Threat Intelligence (CTI) e SOC Tier 3.
Sua missão é analisar o Indicador de Comprometimento (IOC) fornecido, correlacionando rigorosamente os dados do MISP, VirusTotal, AbuseIPDB, AlienVault OTX, Shodan, Geolocalização e MITRE ATT&CK.

Forneça sua resposta em português do Brasil com a seguinte estrutura em Markdown obrigatória:

### 🛡️ Veredito do Analista
- **Classificação**: [Crítico | Alto | Médio | Baixo | Limpo / Falso Positivo]
- **Score de Confiança da Ameaça**: [0 a 100]%
- **Família de Ameaça / Ator**: [Nome do malware, botnet, grupo APT, ou 'Genérico / Não identificado']

### 📋 Resumo Executivo & Análise Técnica
Explique de forma técnica e objetiva o que este indicador representa, contextualizando as evidências encontradas:
- Cite expressamente as evidências e campanhas encontradas no AlienVault OTX (quais pulses, nomes de ameaças ou tags estão associados).
- Utilize ativamente os Comentários da Comunidade do VirusTotal, identificando atores ou campanhas citadas por pesquisadores.
- Cite o comportamento reportado no AbuseIPDB e as detecções do VirusTotal.
- Se o indicador tiver poucas ou nenhuma denúncia em bases tradicionais, utilize obrigatoriamente as evidências do Dossiê Profundo (Certificado SSL/TLS auto-assinado, nó TOR, falta de DNS reverso ou menções web) para inferir se trata-se de infraestrutura descartável recente de ataque.
- Explique o contexto do ataque (ex: C2, Scanner/Brute Force, Phishing, Distribuição de Malware) e o impacto potencial para a organização.

### ⚡ Recomendações & Mitigação Imediata
Ações práticas e prontas para execução pela equipe de SOC/Infraestrutura:
- **Regra de Firewall / Bloqueio de Rede**: (Forneça o comando exato, ex: iptables, PowerShell ou regra genérica de borda).
- **Ação em EDR / Endpoint**: (Isolamento, varredura de hash ou encerramento de processos associados).
- **Investigação de Tráfego Interno**: (Dica de query SIEM/Logs para verificar se algum host interno conversou com o IOC).

INSTRUÇÕES OBRIGATÓRIAS:
1. Mantenha rigorosamente TODOS os campos e títulos acima. NUNCA omita o campo 'Família de Ameaça / Ator' ou qualquer outro item.
2. Utilize ativamente os dados de AlienVault OTX, Comentários do VirusTotal, AbuseIPDB e Dossiê Profundo (Deep Recon).
3. Se a família exata do malware não puder ser confirmada pelos dados, preencha obrigatoriamente como 'Genérico / Não identificado'.
4. Seja direto, técnico e profissional e evite prolixidade desnecessária.
"""

def test_ollama_connection(ollama_url=None):
    """
    Testa a conectividade real com o Ollama e retorna:
    (success: bool, models: list, message: str)
    """
    if not ollama_url:
        ollama_url = db_system.get_setting("ollama_url", "http://localhost:11434")

    from urllib.parse import urlparse
    parsed = urlparse(ollama_url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        logger.warning(f"URL inválida fornecida para o Ollama: {ollama_url}")
        return False, [], f"URL inválida: '{ollama_url}'. Utilize http:// ou https://"

    blocked = {'169.254.169.254', 'metadata.google.internal', 'instance-data', '100.100.100.200'}
    if parsed.hostname in blocked:
        logger.warning(f"Tentativa de SSRF bloqueada para {parsed.hostname}")
        return False, [], "Destino bloqueado por política de segurança Anti-SSRF."

    clean_url = ollama_url.rstrip("/")
    try:
        resp = requests.get(f"{clean_url}/api/tags", timeout=3)
        if resp.status_code == 200:
            raw_models = resp.json().get('models', [])
            models = [m.get('name') for m in raw_models if m.get('name')]
            if models:
                return True, models, f"Conexão bem-sucedida! {len(models)} modelo(s) detectado(s)."
            else:
                return True, [], "Conectado ao Ollama com sucesso, porém nenhum modelo foi baixado ainda no servidor."
        else:
            return False, [], f"Ollama retornou status HTTP {resp.status_code}."
    except requests.exceptions.Timeout:
        return False, [], f"Tempo limite esgotado ao conectar em '{clean_url}' (timeout 3s). Host inalcançável ou fora da rede/VPN."
    except requests.exceptions.ConnectionError:
        return False, [], f"Conexão recusada ou rota inalcançável para '{clean_url}'. Verifique se o Ollama está rodando e acessível."
    except Exception as e:
        return False, [], f"Falha na comunicação com '{clean_url}': {str(e)}"

def list_ollama_models(ollama_url=None):
    """Busca a lista de modelos instalados no servidor Ollama local (sem fallback falso)"""
    success, models, _ = test_ollama_connection(ollama_url)
    return models if success else []

def query_ollama(prompt, system_prompt, model=None, ollama_url=None):
    """Executa a inferência no servidor Ollama local"""
    if not ollama_url:
        ollama_url = db_system.get_setting("ollama_url", "http://localhost:11434")
    if not model:
        model = db_system.get_setting("ollama_model", "deepseek-r1:8b")

    ollama_url = ollama_url.rstrip("/")
    payload = {
        "model": model,
        "prompt": prompt,
        "system": system_prompt,
        "stream": False,
        "keep_alive": "1h",
        "options": {
            "temperature": 0.2,
            "num_predict": 700,
            "num_ctx": 2048
        }
    }

    try:
        resp = requests.post(f"{ollama_url}/api/generate", json=payload, timeout=180)
        if resp.status_code == 200:
            full_response = resp.json().get('response', '')
            
            # Extrai tags <think> do DeepSeek-R1 se presentes
            thinking = ""
            analysis_text = full_response
            think_match = re.search(r"<think>(.*?)</think>", full_response, flags=re.DOTALL)
            if think_match:
                thinking = think_match.group(1).strip()
                analysis_text = re.sub(r"<think>.*?</think>", "", full_response, flags=re.DOTALL).strip()

            return {
                "success": True,
                "model_used": model,
                "provider": "Ollama Local",
                "thinking": thinking,
                "analysis": analysis_text
            }
        else:
            return {"success": False, "error": f"Ollama respondeu com código HTTP {resp.status_code}: {resp.text}"}
    except requests.exceptions.Timeout:
        return {"success": False, "error": "Tempo limite esgotado ao aguardar resposta do Ollama (Timeout de 180s)."}
    except Exception as e:
        return {"success": False, "error": f"Falha na conexão com servidor Ollama ({ollama_url}): {str(e)}"}

def query_gemini(prompt, system_prompt, api_key):
    """Inferência via Google Gemini API REST"""
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
        payload = {
            "contents": [
                {"role": "user", "parts": [{"text": f"{system_prompt}\n\n{prompt}"}]}
            ],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 1024}
        }
        resp = requests.post(url, json=payload, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            text = data['candidates'][0]['content']['parts'][0]['text']
            return {"success": True, "model_used": "gemini-1.5-flash", "provider": "Google Gemini", "thinking": "", "analysis": text}
        return {"success": False, "error": f"Erro na API Gemini ({resp.status_code}): {resp.text}"}
    except Exception as e:
        return {"success": False, "error": f"Erro ao consultar Gemini: {str(e)}"}

def query_openai(prompt, system_prompt, api_key):
    """Inferência via OpenAI API (ChatGPT)"""
    try:
        url = "https://api.openai.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        payload = {
            "model": "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.2
        }
        resp = requests.post(url, headers=headers, json=payload, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            text = data['choices'][0]['message']['content']
            return {"success": True, "model_used": "gpt-4o-mini", "provider": "OpenAI", "thinking": "", "analysis": text}
        return {"success": False, "error": f"Erro na API OpenAI ({resp.status_code}): {resp.text}"}
    except Exception as e:
        return {"success": False, "error": f"Erro ao consultar OpenAI: {str(e)}"}

def query_anthropic(prompt, system_prompt, api_key):
    """Inferência via Anthropic Claude API"""
    try:
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json"
        }
        payload = {
            "model": "claude-3-haiku-20240307",
            "system": system_prompt,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 1024,
            "temperature": 0.2
        }
        resp = requests.post(url, headers=headers, json=payload, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            text = data['content'][0]['text']
            return {"success": True, "model_used": "claude-3-haiku", "provider": "Anthropic Claude", "thinking": "", "analysis": text}
        return {"success": False, "error": f"Erro na API Anthropic ({resp.status_code}): {resp.text}"}
    except Exception as e:
        return {"success": False, "error": f"Erro ao consultar Anthropic: {str(e)}"}

def analyze_ioc_with_ai(ioc_value, ioc_type, misp_data=None, enrichment_data=None, selected_model=None):
    """Monta o contexto completo e despacha a análise para a IA configurada"""
    settings = db_system.get_settings()
    provider = settings.get('ai_provider', 'ollama').lower()

    # Contexto detalhado para enriquecer a inferência
    context_lines = [
        f"**Indicador (IOC)**: {ioc_value}",
        f"**Tipo de Indicador**: {ioc_type.upper()}"
    ]

    if misp_data:
        context_lines.append(f"**Severidade MISP**: {misp_data.get('severity', 'Desconhecida')}")
        context_lines.append(f"**Descrição / Comentário MISP**: {misp_data.get('desc', 'Nenhum')}")
        context_lines.append(f"**Data MISP**: {misp_data.get('date', 'Desconhecida')}")

    if enrichment_data:
        vt = enrichment_data.get('vt_data')
        if vt and isinstance(vt, dict) and not vt.get('error') and not vt.get('not_found'):
            context_lines.append(f"**VirusTotal Detections**: {vt.get('malicious', 0)} motores detectaram como malicioso, {vt.get('suspicious', 0)} suspeito, {vt.get('harmless', 0)} inofensivo.")
            if vt.get('tags'):
                context_lines.append(f"**VirusTotal Tags**: {', '.join(vt.get('tags'))}")

        abuse = enrichment_data.get('abuse_data')
        if abuse and isinstance(abuse, dict) and not abuse.get('error'):
            context_lines.append(f"**AbuseIPDB Score**: {abuse.get('abuse_score', 0)}% (Total de denúncias: {abuse.get('total_reports', 0)})")
            context_lines.append(f"**ISP / Organização**: {abuse.get('isp', 'N/A')}")

        geo = enrichment_data.get('geo_data')
        if geo and isinstance(geo, dict):
            context_lines.append(f"**Geolocalização**: {geo.get('city', '')}, {geo.get('regionName', '')}, {geo.get('country', '')} ({geo.get('countryCode', '')}) | ASN: {geo.get('as', 'N/A')}")

        mitre = enrichment_data.get('mitre_tags')
        if mitre:
            tactics_str = ", ".join([f"{t.get('id')} ({t.get('tactic')}: {t.get('name')})" for t in mitre])
            context_lines.append(f"**Mapeamento MITRE ATT&CK Sugerido**: {tactics_str}")

        otx = enrichment_data.get('otx_data')
        if otx and isinstance(otx, dict):
            p_count = otx.get('pulse_count', 0)
            if p_count > 0:
                context_lines.append(f"**AlienVault OTX**: Presente em {p_count} campanhas de ameaça na comunidade.")
                pulses = otx.get('pulses', [])
                if pulses:
                    pulse_details = []
                    for p in pulses[:4]:
                        p_str = f"Campanha '{p.get('name', 'Sem nome')}'"
                        if p.get('adversary'):
                            p_str += f" (Ator/Ameaça: {p.get('adversary')})"
                        if p.get('description'):
                            clean_d = p.get('description', '').replace('\n', ' ')[:130]
                            p_str += f" - Detalhes: {clean_d}..."
                        pulse_details.append(p_str)
                    context_lines.append(f"**Campanhas AlienVault OTX Detalhadas**:\n  - " + "\n  - ".join(pulse_details))
                if otx.get('tags'):
                    context_lines.append(f"**Tags de Ameaça AlienVault OTX**: {', '.join(otx.get('tags')[:10])}")
            else:
                context_lines.append("**AlienVault OTX**: 0 pulses reportados na comunidade para este indicador.")

        # Comentários da Comunidade VirusTotal
        if vt and isinstance(vt, dict) and vt.get('comments'):
            vt_comments = vt.get('comments', [])
            if vt_comments:
                c_texts = [f"[{c.get('date', 'Data n/d')}] {c.get('text', '')}" for c in vt_comments[:4]]
                context_lines.append(f"**Comentários de Pesquisadores no VirusTotal**:\n  - " + "\n  - ".join(c_texts))

        # Dossiê Profundo (Deep Recon: SSL/TLS, Banner, TOR, PTR, RDAP, Web Mentions)
        deep = enrichment_data.get('deep_recon') or (geo.get('deep_recon') if (geo and isinstance(geo, dict)) else None)
        if deep and isinstance(deep, dict):
            sb = deep.get('ssl_banner') or {}
            if sb.get('has_ssl') and sb.get('ssl_cert'):
                cert = sb['ssl_cert']
                self_signed_str = " (AUTO-ASSINADO / SELF-SIGNED)" if cert.get('is_self_signed') else ""
                context_lines.append(f"**Inspeção SSL/TLS (HTTPS)**: Certificado ativo{self_signed_str} | CN: {cert.get('subject_cn')} | Emissor: {cert.get('issuer_cn')} ({cert.get('issuer_org')}) | Validade: {cert.get('valid_to', '')}")
                if cert.get('sans'):
                    context_lines.append(f"**Nomes Alternativos SSL (SANs)**: {', '.join(cert['sans'])}")
            if sb.get('http_banner'):
                context_lines.append(f"**Banner HTTP / Servidor**: {sb['http_banner']}")

            tor = deep.get('tor_data') or {}
            if tor.get('is_tor_exit_node'):
                context_lines.append(f"**Alerta de Rede Anônima**: ⚠️ Este IP é um NÓ DE SAÍDA TOR ATIVO (Tor Exit Node).")

            dr = deep.get('dns_rdap') or {}
            if dr.get('reverse_dns'):
                context_lines.append(f"**DNS Reverso (PTR)**: {dr['reverse_dns']}")
            if dr.get('rdap'):
                context_lines.append(f"**Entidade Registradora (RDAP)**: {dr['rdap'].get('name', '')} ({dr['rdap'].get('country', '')})")

            wm = deep.get('web_mentions') or []
            if wm:
                context_lines.append(f"**Menções na Web / Threat Feeds Externos**:\n  - " + "\n  - ".join(wm[:3]))

    prompt = "Analise o seguinte Indicador de Comprometimento (IOC) e gere o parecer executivo:\n\n" + "\n".join(context_lines)

    # Execução pelo provedor selecionado
    if provider == "gemini":
        api_key = settings.get('gemini_api_key', '')
        if not api_key:
            return {"success": False, "error": "Chave de API do Google Gemini não configurada."}
        res = query_gemini(prompt, THREAT_INTEL_SYSTEM_PROMPT, api_key)
    elif provider == "openai":
        api_key = settings.get('openai_api_key', '')
        if not api_key:
            return {"success": False, "error": "Chave de API da OpenAI não configurada."}
        res = query_openai(prompt, THREAT_INTEL_SYSTEM_PROMPT, api_key)
    elif provider == "anthropic":
        api_key = settings.get('anthropic_api_key', '')
        if not api_key:
            return {"success": False, "error": "Chave de API da Anthropic Claude não configurada."}
        res = query_anthropic(prompt, THREAT_INTEL_SYSTEM_PROMPT, api_key)
    else: # Ollama Local
        ollama_url = settings.get('ollama_url', 'http://localhost:11434')
        model = selected_model or settings.get('ollama_model', 'deepseek-r1:8b')
        res = query_ollama(prompt, THREAT_INTEL_SYSTEM_PROMPT, model=model, ollama_url=ollama_url)

    if res.get('success'):
        # Salva em cache para reuso instantâneo
        db_system.save_cached_enrichment(ioc_value, ioc_type, ai_analysis=res)

    return res
