import requests
import json
import logging
import base64
import ipaddress
import db_system

logger = logging.getLogger("enrichment_service")

def country_code_to_flag(code):
    if not code or len(code) != 2:
        return "🌐"
    return "".join(chr(127397 + ord(c.upper())) for c in code)

def get_mitre_tactics_for_ioc(ioc_type, value="", comment="", vt_tags=None):
    """Mapeia táticas e técnicas do MITRE ATT&CK com base no tipo e contexto do IOC"""
    tactics = []
    text_context = (value + " " + comment).lower()

    if ioc_type == "ips":
        tactics.append({"id": "T1071", "tactic": "Command and Control", "name": "Application Layer Protocol"})
        tactics.append({"id": "T1105", "tactic": "Command and Control", "name": "Ingress Tool Transfer"})
    elif ioc_type in ["domains", "urls"]:
        if any(w in text_context for w in ["phish", "login", "bank", "account", "verify", "secure"]):
            tactics.append({"id": "T1566", "tactic": "Initial Access", "name": "Phishing"})
        else:
            tactics.append({"id": "T1071.001", "tactic": "Command and Control", "name": "Web Protocols"})
            tactics.append({"id": "T1583.001", "tactic": "Resource Development", "name": "Domains"})
    elif ioc_type == "filehashs":
        tactics.append({"id": "T1204", "tactic": "Execution", "name": "User Execution"})
        tactics.append({"id": "T1027", "tactic": "Defense Evasion", "name": "Obfuscated Files or Information"})

    if vt_tags:
        for tag in vt_tags:
            tag_l = tag.lower()
            if "trojan" in tag_l or "rat" in tag_l or "c2" in tag_l:
                if not any(t['id'] == "T1219" for t in tactics):
                    tactics.append({"id": "T1219", "tactic": "Command and Control", "name": "Remote Access Software"})
            if "ransomware" in tag_l:
                if not any(t['id'] == "T1486" for t in tactics):
                    tactics.append({"id": "T1486", "tactic": "Impact", "name": "Data Encrypted for Impact"})

    return tactics

def get_geolocation(ip):
    """Consulta geolocalização do IP usando ip-api.com ou ipinfo.io conforme configurado"""
    provider = db_system.get_setting("geoip_provider", "ip-api")
    api_key = db_system.get_setting("geoip_api_key", "").strip()

    try:
        if provider == "ipinfo" and api_key:
            url = f"https://ipinfo.io/{ip}/json?token={api_key}"
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                loc = data.get('loc', '').split(',')
                lat = float(loc[0]) if len(loc) == 2 else None
                lon = float(loc[1]) if len(loc) == 2 else None
                cc = data.get('country', '')
                return {
                    "status": "success",
                    "country": data.get('country', ''),
                    "countryCode": cc,
                    "regionName": data.get('region', ''),
                    "city": data.get('city', ''),
                    "lat": lat,
                    "lon": lon,
                    "isp": data.get('org', ''),
                    "org": data.get('org', ''),
                    "as": data.get('org', ''),
                    "flag": country_code_to_flag(cc)
                }
        else:
            # Padrão ip-api (gratuito ou com Pro Key)
            base_url = "https://pro.ip-api.com/json/" if api_key else "http://ip-api.com/json/"
            url = f"{base_url}{ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,query"
            if api_key:
                url += f"&key={api_key}"
            try:
                resp = requests.get(url, timeout=4)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get('status') == 'success':
                        data['flag'] = country_code_to_flag(data.get('countryCode', ''))
                        return data
            except Exception as e_ipapi:
                logger.warning(f"ip-api falhou para {ip} ({e_ipapi}), tentando fallback HTTPS freeipapi...")

            # Fallback 2: freeipapi.com via HTTPS
            try:
                resp2 = requests.get(f"https://freeipapi.com/api/json/{ip}", timeout=4)
                if resp2.status_code == 200:
                    d2 = resp2.json()
                    cc = d2.get("countryCode", "")
                    return {
                        "status": "success",
                        "country": d2.get("countryName", ""),
                        "countryCode": cc,
                        "regionName": d2.get("regionName", ""),
                        "city": d2.get("cityName", ""),
                        "lat": float(d2.get("latitude", 0)) if d2.get("latitude") is not None else None,
                        "lon": float(d2.get("longitude", 0)) if d2.get("longitude") is not None else None,
                        "isp": d2.get("asnOrganization", ""),
                        "org": d2.get("asnOrganization", ""),
                        "as": f"AS{d2.get('asn', '')}",
                        "query": ip,
                        "flag": country_code_to_flag(cc)
                    }
            except Exception as e_fb:
                logger.error(f"Fallback freeipapi falhou para {ip}: {e_fb}")
    except Exception as e:
        logger.error(f"Erro geral na geolocalização do IP {ip}: {e}")
    return None

def query_virustotal_comments(ioc_value, ioc_type, api_key):
    """Busca os comentários mais recentes da comunidade do VirusTotal"""
    if not api_key:
        return []
    try:
        col_map = {
            "ips": "ip_addresses",
            "domains": "domains",
            "urls": "urls",
            "filehashs": "files"
        }
        col = col_map.get(ioc_type)
        if not col:
            return []
            
        val = ioc_value
        if ioc_type == "urls":
            val = base64.urlsafe_b64encode(ioc_value.encode()).decode().strip("=")

        url = f"https://www.virustotal.com/api/v3/{col}/{val}/comments?limit=8"
        headers = {"x-apikey": api_key, "Accept": "application/json"}
        resp = requests.get(url, headers=headers, timeout=6)
        if resp.status_code == 200:
            raw_comments = resp.json().get('data', [])
            comments = []
            for item in raw_comments:
                attrs = item.get('attributes', {})
                txt = (attrs.get('text') or '').strip()
                if txt:
                    ts = attrs.get('date', 0)
                    date_str = ""
                    if ts:
                        try:
                            import datetime
                            date_str = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d')
                        except Exception:
                            pass
                    comments.append({
                        "text": txt[:400],
                        "date": date_str,
                        "tags": attrs.get('tags', []),
                        "votes": attrs.get('votes', {})
                    })
            return comments
    except Exception as e:
        logger.warning(f"Erro ao buscar comentários do VirusTotal para {ioc_value}: {e}")
    return []

def query_virustotal(ioc_value, ioc_type):
    """Consulta a API v3 do VirusTotal"""
    api_key = db_system.get_setting("virustotal_api_key", "").strip()
    if not api_key:
        return {"error": "Chave de API do VirusTotal não configurada nas Configurações."}

    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }

    try:
        if ioc_type == "ips":
            endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}"
        elif ioc_type == "domains":
            endpoint = f"https://www.virustotal.com/api/v3/domains/{ioc_value}"
        elif ioc_type == "urls":
            # URL ID no VT é base64 url-safe sem padding
            url_id = base64.urlsafe_b64encode(ioc_value.encode()).decode().strip("=")
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        elif ioc_type == "filehashs":
            endpoint = f"https://www.virustotal.com/api/v3/files/{ioc_value}"
        else:
            return None

        resp = requests.get(endpoint, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json().get('data', {}).get('attributes', {})
            stats = data.get('last_analysis_stats', {})
            
            # Extrai motores antivírus com detecções positivas
            analysis_results = data.get('last_analysis_results', {})
            malware_engines = []
            for engine, res in analysis_results.items():
                if res.get('category') in ['malicious', 'suspicious']:
                    malware_engines.append({
                        "engine": engine,
                        "result": res.get('result') or 'Malicious',
                        "category": res.get('category')
                    })

            # Busca comentários da comunidade do VirusTotal
            comments = query_virustotal_comments(ioc_value, ioc_type, api_key)

            return {
                "malicious": stats.get('malicious', 0),
                "suspicious": stats.get('suspicious', 0),
                "harmless": stats.get('harmless', 0),
                "undetected": stats.get('undetected', 0),
                "reputation": data.get('reputation', 0),
                "tags": data.get('tags', []),
                "network": data.get('network', ''),
                "as_owner": data.get('as_owner', ''),
                "malware_engines": malware_engines,
                "comments": comments
            }
        elif resp.status_code == 404:
            return {"not_found": True, "message": "Não encontrado na base do VirusTotal."}
        elif resp.status_code == 429:
            return {"error": "Limite de requisições excedido no VirusTotal (Rate Limit)."}
        else:
            return {"error": f"VirusTotal respondeu com status {resp.status_code}."}
    except Exception as e:
        logger.error(f"Erro ao consultar VirusTotal para {ioc_value}: {e}")
        return {"error": f"Erro de conexão com VirusTotal: {str(e)}"}

def query_abuseipdb(ip):
    """Consulta a API v2 do AbuseIPDB para IPs incluindo relatórios e comentários"""
    api_key = db_system.get_setting("abuseipdb_api_key", "").strip()
    if not api_key:
        return {"error": "Chave de API do AbuseIPDB não configurada nas Configurações."}

    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 180,
        "verbose": ""
    }

    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        if resp.status_code == 200:
            data = resp.json().get('data', {})
            
            # Extrai os comentários reais dos relatórios recentes
            reports = []
            for r in data.get('reports', [])[:8]:
                c_text = r.get('comment', '').strip()
                if c_text:
                    reports.append({
                        "reported_at": r.get('reportedAt', '')[:10],
                        "comment": c_text,
                        "reporter_country": r.get('reporterCountryCode', '')
                    })

            return {
                "abuse_score": data.get('abuseConfidenceScore', 0),
                "total_reports": data.get('totalReports', 0),
                "last_reported_at": data.get('lastReportedAt', 'Nunca'),
                "usage_type": data.get('usageType', 'Desconhecido'),
                "domain": data.get('domain', ''),
                "isp": data.get('isp', ''),
                "country_code": data.get('countryCode', ''),
                "reports": reports
            }
        elif resp.status_code == 429:
            return {"error": "Limite de requisições excedido no AbuseIPDB (Rate Limit)."}
        else:
            return {"error": f"AbuseIPDB respondeu com status {resp.status_code}."}
    except Exception as e:
        logger.error(f"Erro ao consultar AbuseIPDB para {ip}: {e}")
        return {"error": f"Erro de conexão com AbuseIPDB: {str(e)}"}

def query_shodan_internetdb(ip):
    """Consulta portas abertas, CVEs e hostnames via Shodan InternetDB (Gratuito, sem API key)"""
    try:
        url = f"https://internetdb.shodan.io/{ip}"
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "ports": data.get("ports", []),
                "vulns": data.get("vulns", []),
                "cpes": data.get("cpes", []),
                "hostnames": data.get("hostnames", [])
            }
        elif resp.status_code == 404:
            return {"ports": [], "vulns": [], "hostnames": []}
    except Exception as e:
        logger.error(f"Erro ao consultar Shodan InternetDB para {ip}: {e}")
    return None

def query_alienvault_otx(ioc_value, ioc_type):
    """Consulta a API do AlienVault OTX para extrair contagem de Pulses, campanhas ativas e tags"""
    try:
        type_map = {
            "ips": "IPv4",
            "domains": "domain",
            "urls": "url",
            "filehashs": "file"
        }
        otx_type = type_map.get(ioc_type, "IPv4")
        url = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{ioc_value}/general"

        api_key = db_system.get_setting("otx_api_key", "").strip()
        headers = {"Accept": "application/json"}
        if api_key:
            headers["X-OTX-API-KEY"] = api_key

        resp = requests.get(url, headers=headers, timeout=6)
        if resp.status_code == 200:
            data = resp.json()
            pulse_info = data.get('pulse_info', {})
            pulses_raw = pulse_info.get('pulses', [])

            pulses = []
            all_tags = set()
            for p in pulses_raw[:6]:
                p_tags = p.get('tags', [])
                all_tags.update([t.lower() for t in p_tags if t])
                author_val = (p.get('author') or {}).get('username') if isinstance(p.get('author'), dict) else (p.get('author_name') or 'Comunidade OTX')
                pulses.append({
                    "id": p.get('id'),
                    "name": p.get('name', 'Sem nome'),
                    "description": p.get('description', '') or '',
                    "author": author_val or 'Comunidade OTX',
                    "created": (p.get('created', '') or '')[:10],
                    "tags": p_tags[:4],
                    "adversary": p.get('adversary', '')
                })

            return {
                "pulse_count": pulse_info.get('count', 0),
                "pulses": pulses,
                "tags": list(all_tags)[:12]
            }
        elif resp.status_code == 404:
            return {"pulse_count": 0, "pulses": [], "tags": []}
    except Exception as e:
        logger.error(f"Erro ao consultar AlienVault OTX para {ioc_value}: {e}")
    return {"pulse_count": 0, "pulses": [], "tags": []}

# --- Motor de Reconhecimento Profundo (Deep Recon) ---

def inspect_ssl_and_banner(ip):
    """Inspeção ativa de certificado SSL/TLS (porta 443) e banner HTTP/Server (porta 80/443)"""
    import socket
    import ssl
    result = {
        "has_ssl": False,
        "ssl_cert": None,
        "http_banner": None,
        "open_ports_probed": []
    }

    # 1. Probe SSL na 443
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, 443), timeout=2.5) as sock:
            result["open_ports_probed"].append(443)
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if not cert:
                    der_cert = ssock.getpeercert(binary_form=True)
                    if der_cert:
                        result["has_ssl"] = True
                        result["ssl_cert"] = {
                            "subject_cn": "Certificado Binário (DER)",
                            "issuer_cn": "Auto-Assinado ou Não-Padrão (Self-Signed)",
                            "is_self_signed": True,
                            "valid_to": "Ativo"
                        }
                else:
                    subject = dict(x[0] for x in cert.get('subject', []))
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    sans = [x[1] for x in cert.get('subjectAltName', []) if x[0] == 'DNS']
                    is_self_signed = (subject == issuer) or ('commonName' in subject and subject.get('commonName') == issuer.get('commonName'))
                    result["has_ssl"] = True
                    result["ssl_cert"] = {
                        "subject_cn": subject.get('commonName', 'N/A'),
                        "issuer_cn": issuer.get('commonName', 'N/A'),
                        "issuer_org": issuer.get('organizationName', 'N/A'),
                        "valid_from": cert.get('notBefore', ''),
                        "valid_to": cert.get('notAfter', ''),
                        "sans": sans[:6],
                        "is_self_signed": is_self_signed
                    }
    except Exception:
        pass

    # 2. Probe HTTP na 80 e 8080
    for p in [80, 8080]:
        try:
            with socket.create_connection((ip, p), timeout=2.0) as s:
                if p not in result["open_ports_probed"]:
                    result["open_ports_probed"].append(p)
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                resp = s.recv(1024).decode('utf-8', errors='ignore')
                for line in resp.splitlines():
                    if line.lower().startswith('server:'):
                        result["http_banner"] = line.split(':', 1)[1].strip()
                        break
                if result["http_banner"]:
                    break
        except Exception:
            pass

    return result

_tor_exit_cache = {"ips": set(), "timestamp": 0}

def check_tor_and_anonymity(ip):
    """Verifica se o IP é um nó de saída TOR ativo ou pertence a serviços de anonimização"""
    import time
    now = time.time()
    if not _tor_exit_cache["ips"] or (now - _tor_exit_cache["timestamp"] > 43200):
        try:
            resp = requests.get("https://check.torproject.org/torbulkexitlist", timeout=5)
            if resp.status_code == 200:
                tor_ips = set(line.strip() for line in resp.text.splitlines() if line.strip())
                _tor_exit_cache["ips"] = tor_ips
                _tor_exit_cache["timestamp"] = now
        except Exception as e:
            logger.warning(f"Erro ao baixar lista de saída Tor: {e}")

    is_tor = ip in _tor_exit_cache["ips"]
    return {
        "is_tor_exit_node": is_tor,
        "tor_risk": "CRÍTICO" if is_tor else "NENHUM"
    }

def get_reverse_dns_and_rdap(ip):
    """Consulta PTR reverso e dados básicos de RDAP / Whois"""
    import socket
    ptr = None
    try:
        ptr = socket.gethostbyaddr(ip)[0]
    except Exception:
        pass

    rdap_info = None
    try:
        resp = requests.get(f"https://rdap.arin.net/registry/ip/{ip}", timeout=3)
        if resp.status_code == 200:
            d = resp.json()
            rdap_info = {
                "name": d.get('name', ''),
                "handle": d.get('handle', ''),
                "country": d.get('country', ''),
                "start_address": d.get('startAddress', ''),
                "end_address": d.get('endAddress', '')
            }
    except Exception:
        pass

    return {
        "reverse_dns": ptr or "Sem registro reverso (No PTR)",
        "rdap": rdap_info
    }

def search_web_threat_mentions(ioc_value):
    """Busca menções públicas ao IOC em relatórios e fóruns via DuckDuckGo Instant API"""
    try:
        url = f"https://api.duckduckgo.com/?q={ioc_value}+threat+malware&format=json&no_html=1&skip_disambig=1"
        resp = requests.get(url, timeout=3)
        if resp.status_code == 200:
            d = resp.json()
            abstract = d.get('AbstractText', '')
            topics = d.get('RelatedTopics', [])
            mentions = []
            if abstract:
                mentions.append(abstract[:200])
            for t in topics[:3]:
                if isinstance(t, dict) and t.get('Text'):
                    mentions.append(t['Text'][:150])
            return mentions[:3]
    except Exception:
        pass
    return []

def query_greynoise(ip_value):
    """Consulta telemetria global de tráfego de ataques e scanners via GreyNoise Community API"""
    try:
        url = f"https://api.greynoise.io/v3/community/{ip_value}"
        headers = {"Accept": "application/json"}
        try:
            settings = db_system.get_settings()
            gn_key = settings.get('greynoise_api_key', '')
            if gn_key:
                headers["key"] = gn_key
        except Exception:
            pass

        resp = requests.get(url, headers=headers, timeout=4)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "active_traffic": data.get("noise", False),
                "riot_benign": data.get("riot", False),
                "classification": data.get("classification", "unknown"),
                "actor_or_tool": data.get("name", ""),
                "last_seen": data.get("last_seen", ""),
                "viz_url": data.get("link", f"https://viz.greynoise.io/ip/{ip_value}"),
                "message": data.get("message", "Telemetria ativa")
            }
        elif resp.status_code == 404:
            return {
                "active_traffic": False,
                "riot_benign": False,
                "classification": "unobserved",
                "actor_or_tool": "",
                "last_seen": "",
                "viz_url": f"https://viz.greynoise.io/ip/{ip_value}",
                "message": "Nenhum tráfego de ataque global detectado nas últimas semanas"
            }
    except Exception as e:
        logger.debug(f"Erro ao consultar GreyNoise para {ip_value}: {e}")
    
    return {
        "active_traffic": False,
        "riot_benign": False,
        "classification": "unknown",
        "actor_or_tool": "",
        "last_seen": "",
        "viz_url": f"https://viz.greynoise.io/ip/{ip_value}",
        "message": "Indisponível no momento"
    }

def get_deep_recon(ioc_value, ioc_type):
    """Agrega os 5 pilares do Deep Recon em um único relatório (incluindo GreyNoise Live Telemetry)"""
    is_ip = (ioc_type == "ips")
    ssl_banner = inspect_ssl_and_banner(ioc_value) if is_ip else {"has_ssl": False, "ssl_cert": None, "http_banner": None}
    tor_data = check_tor_and_anonymity(ioc_value) if is_ip else {"is_tor_exit_node": False, "tor_risk": "NENHUM"}
    dns_rdap = get_reverse_dns_and_rdap(ioc_value) if is_ip else {"reverse_dns": "N/A", "rdap": None}
    web_mentions = search_web_threat_mentions(ioc_value)
    greynoise = query_greynoise(ioc_value) if is_ip else None

    return {
        "ssl_banner": ssl_banner,
        "tor_data": tor_data,
        "dns_rdap": dns_rdap,
        "web_mentions": web_mentions,
        "greynoise": greynoise
    }

def enrich_ioc(ioc_value, ioc_type, comment="", force_refresh=False):
    """Enriquece o IOC combinando VirusTotal, AbuseIPDB, Shodan InternetDB, AlienVault OTX, GeoIP, Deep Recon e MITRE ATT&CK"""
    ioc_val = ioc_value.strip().lower()

    if not force_refresh:
        cached = db_system.get_cached_enrichment(ioc_val)
        if cached and (cached.get('vt_data') or cached.get('geo_data') or cached.get('abuse_data')):
            abuse_cached = cached.get('abuse_data')
            need_save = False
            if ioc_type == "ips" and abuse_cached and isinstance(abuse_cached, dict) and 'reports' not in abuse_cached:
                cached['abuse_data'] = query_abuseipdb(ioc_val)
                need_save = True
            if not cached.get('shodan_data') and ioc_type == "ips":
                cached['shodan_data'] = query_shodan_internetdb(ioc_val)
                need_save = True
            if not cached.get('otx_data') or not cached.get('otx_data', {}).get('pulses') or not any('description' in p for p in cached.get('otx_data', {}).get('pulses', [])):
                cached['otx_data'] = query_alienvault_otx(ioc_val, ioc_type)
                need_save = True
            # Adiciona Deep Recon ao cache se não existir
            geo_cached = cached.get('geo_data') or {}
            if 'deep_recon' not in geo_cached:
                cached_deep_recon = get_deep_recon(ioc_val, ioc_type)
                geo_cached['deep_recon'] = cached_deep_recon
                cached['geo_data'] = geo_cached
                need_save = True

            if need_save:
                db_system.save_cached_enrichment(
                    ioc_value=ioc_val,
                    ioc_type=ioc_type,
                    vt_data=cached.get('vt_data'),
                    abuse_data=cached.get('abuse_data'),
                    geo_data=cached.get('geo_data'),
                    mitre_tags=cached.get('mitre_tags'),
                    shodan_data=cached.get('shodan_data'),
                    otx_data=cached.get('otx_data')
                )
            cached['deep_recon'] = cached.get('geo_data', {}).get('deep_recon')
            return cached

    vt_data = query_virustotal(ioc_val, ioc_type)
    abuse_data = query_abuseipdb(ioc_val) if ioc_type == "ips" else None
    geo_data = get_geolocation(ioc_val) if ioc_type == "ips" else None
    shodan_data = query_shodan_internetdb(ioc_val) if ioc_type == "ips" else None
    otx_data = query_alienvault_otx(ioc_val, ioc_type)
    deep_recon = get_deep_recon(ioc_val, ioc_type)

    if geo_data:
        geo_data['deep_recon'] = deep_recon
    elif is_ip := (ioc_type == "ips"):
        geo_data = {'deep_recon': deep_recon}
    
    vt_tags = vt_data.get('tags', []) if vt_data and isinstance(vt_data, dict) else []
    combined_tags = list(set(vt_tags + (otx_data.get('tags', []) if otx_data else [])))
    mitre_tags = get_mitre_tactics_for_ioc(ioc_type, ioc_val, comment, combined_tags)

    db_system.save_cached_enrichment(
        ioc_value=ioc_val,
        ioc_type=ioc_type,
        vt_data=vt_data,
        abuse_data=abuse_data,
        geo_data=geo_data,
        mitre_tags=mitre_tags,
        shodan_data=shodan_data,
        otx_data=otx_data
    )

    return {
        "ioc_value": ioc_val,
        "ioc_type": ioc_type,
        "vt_data": vt_data,
        "abuse_data": abuse_data,
        "geo_data": geo_data,
        "shodan_data": shodan_data,
        "otx_data": otx_data,
        "deep_recon": deep_recon,
        "mitre_tags": mitre_tags
    }

_target_cache = {"data": None, "timestamp": 0}

def resolve_target_location(client_ip=None):
    """
    Resolve dinamicamente a geolocalização do operador/SOC pelo IP de acesso
    (com cache de 10 minutos para não realizar requisições redundantes).
    """
    import time
    now = time.time()
    if _target_cache["data"] and (now - _target_cache["timestamp"] < 600):
        if not client_ip or client_ip == _target_cache["data"].get("client_ip"):
            return _target_cache["data"]

    is_public = False
    if client_ip:
        try:
            ip_obj = ipaddress.ip_address(client_ip)
            if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local):
                is_public = True
        except ValueError:
            pass

    geo = None
    resolved_ip = client_ip if is_public else None

    # Se for IP público direto do cliente (ex: X-Forwarded-For ou acesso remoto)
    if resolved_ip:
        geo = get_geolocation(resolved_ip)

    # Se for acesso local / container (127.0.0.1 ou 172.19.x.x), resolve a saída pública da rede
    if not geo:
        try:
            resp = requests.get("https://freeipapi.com/api/json", timeout=3)
            if resp.status_code == 200:
                d = resp.json()
                cc = d.get("countryCode", "BR")
                resolved_ip = d.get("ipAddress", "")
                geo = {
                    "country": d.get("countryName", "Brasil"),
                    "city": d.get("cityName", "Sede Operacional"),
                    "lat": float(d.get("latitude", -15.7801)),
                    "lon": float(d.get("longitude", -47.9292)),
                    "flag": country_code_to_flag(cc),
                    "ip": resolved_ip
                }
        except Exception as e:
            logger.warning(f"Não foi possível autodetectar geolocalização do IP público: {e}")

    if geo and geo.get('lat') and geo.get('lon'):
        city_name = geo.get('city') or geo.get('country') or "Brasil"
        target_info = {
            "name": f"SOC Central ({city_name})",
            "city": geo.get('city', 'Sede Operacional'),
            "country": geo.get('country', 'Brasil'),
            "lat": float(geo['lat']),
            "lon": float(geo['lon']),
            "flag": geo.get('flag', '🇧🇷'),
            "client_ip": resolved_ip or client_ip or "Localhost"
        }
        _target_cache["data"] = target_info
        _target_cache["timestamp"] = now
        return target_info

    # Fallback seguro padrão (Brasil Central)
    return {
        "name": "SOC Brasil (Headquarters)",
        "city": "São Paulo / Brasília",
        "country": "Brasil",
        "lat": -15.7801,
        "lon": -47.9292,
        "flag": "🇧🇷",
        "client_ip": client_ip or "127.0.0.1"
    }

