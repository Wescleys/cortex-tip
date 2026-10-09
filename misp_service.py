import os
import json
import logging
import datetime
import ipaddress
import mysql.connector
from pymisp import PyMISP, MISPEvent, MISPAttribute
import db_system

logger = logging.getLogger("misp_service")

CACHE_FOLDER = "cache"
os.makedirs(CACHE_FOLDER, exist_ok=True)

CACHE_FILES = {
    "ips": os.path.join(CACHE_FOLDER, "ips.json"),
    "domains": os.path.join(CACHE_FOLDER, "domains.json"),
    "urls": os.path.join(CACHE_FOLDER, "urls.json"),
    "filehashs": os.path.join(CACHE_FOLDER, "filehashs.json")
}

SEVERITY_MAP = {
    '1': 'Alta',
    '2': 'Média',
    '3': 'Baixa',
    '4': 'Indefinida'
}

# Categorias e tipos padrão do MISP para o formulário
MISP_CATEGORIES = [
    "Network activity",
    "Payload delivery",
    "Payload installation",
    "Artifacts dropped",
    "Antivirus detection",
    "External analysis",
    "Financial fraud",
    "Internal reference",
    "Other"
]

MISP_TYPES_BY_CATEGORY = {
    "Network activity": ["ip-src", "ip-dst", "domain", "hostname", "url", "uri", "user-agent", "email-src", "email-dst"],
    "Payload delivery": ["md5", "sha1", "sha256", "filename", "url", "email-attachment"],
    "Payload installation": ["md5", "sha1", "sha256", "filename", "regkey"],
    "Artifacts dropped": ["md5", "sha1", "sha256", "filename", "mutex"],
    "Antivirus detection": ["yara", "signature"],
    "External analysis": ["link", "comment", "text"],
    "Financial fraud": ["iban", "bic", "btc"],
    "Internal reference": ["comment", "text", "link"],
    "Other": ["text", "comment", "other"]
}

MISP_DISTRIBUTIONS = [
    {"value": "0", "label": "This organization only"},
    {"value": "1", "label": "This community only"},
    {"value": "2", "label": "Connected communities"},
    {"value": "3", "label": "All communities"},
    {"value": "5", "label": "Inherit event"}
]

def is_private_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local
    except ValueError:
        return False

def filter_ioc_data(raw_list, ioc_type):
    filtered = []
    seen_values = set()

    for item in raw_list:
        val = str(item.get('value', '')).strip().lower()
        if not val or val in seen_values:
            continue

        if ioc_type == "ips":
            if "/" in val or is_private_ip(val):
                continue
        if ioc_type in ["domains", "urls"]:
            if "google.com" in val:
                continue

        seen_values.add(val)
        
        ts = item.get('timestamp')
        date_str = datetime.datetime.fromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M') if ts else "Desconhecida"
        
        sev_id = str(item.get('threat_level_id', '4'))
        severity = SEVERITY_MAP.get(sev_id, 'Indefinida')

        filtered.append({
            "value": val,
            "desc": item.get('comment') or item.get('info') or "Sem descrição",
            "date": date_str,
            "severity": severity,
            "type": ioc_type,
            "event_id": item.get('event_id', '')
        })

    return filtered

# --- Testes de Conexão ---

def test_mysql_connection(host, user, password, database):
    try:
        conn = mysql.connector.connect(
            host=host,
            user=user,
            password=password,
            database=database,
            connection_timeout=5
        )
        if conn.is_connected():
            conn.close()
            return True, "Conexão com MySQL do MISP estabelecida com sucesso!"
    except Exception as e:
        return False, f"Erro ao conectar ao MySQL: {str(e)}"
    return False, "Não foi possível estabelecer conexão."

def test_api_connection(url, api_key, verify_ssl=False):
    if not url or not api_key:
        return False, "URL e API Key são obrigatórios."
    try:
        misp = PyMISP(url, api_key, ssl=verify_ssl, timeout=10)
        version = misp.misp_instance_version
        if callable(version):
            version = version()
        if version and isinstance(version, dict) and 'version' in version:
            return True, f"Conexão com API MISP bem-sucedida! Versão: {version['version']}"
        return True, "Conexão com API MISP estabelecida com sucesso!"
    except Exception as e:
        return False, f"Erro na API do MISP: {str(e)}"

# --- Sincronização / Leitura ---

def fetch_iocs_via_mysql():
    settings = db_system.get_settings()
    host = settings.get('misp_mysql_host', '').strip()
    user = settings.get('misp_mysql_user', '').strip()
    password = settings.get('misp_mysql_password', '')
    database = settings.get('misp_mysql_database', '').strip()

    if not host or not user or not database:
        logger.warning("Configurações do MySQL do MISP incompletas no Painel de Configurações.")
        return {}

    db_config = {
        'host': host,
        'user': user,
        'password': password,
        'database': database,
        'connection_timeout': 5
    }

    logger.info("[INFO] Atualizando IOCs via banco MySQL do MISP...")
    db = mysql.connector.connect(**db_config)
    cursor = db.cursor(dictionary=True)

    base_query = """
        SELECT a.value1 as value, a.comment, a.timestamp, e.threat_level_id, e.info, a.event_id
        FROM attributes a
        JOIN events e ON a.event_id = e.id
        WHERE a.type {}
    """

    queries = {
        "ips": base_query.format("IN ('ip-dst', 'ip-src')"),
        "domains": base_query.format("= 'domain'"),
        "urls": base_query.format("= 'url'"),
        "filehashs": base_query.format("IN ('md5', 'sha1', 'sha256')")
    }

    updated_counts = {}

    for key, query in queries.items():
        cursor.execute(query)
        raw_data = cursor.fetchall()
        clean_data = filter_ioc_data(raw_data, key)

        temp_file = CACHE_FILES[key] + ".tmp"
        with open(temp_file, "w", encoding="utf-8") as file:
            json.dump(clean_data, file)

        os.replace(temp_file, CACHE_FILES[key])
        updated_counts[key] = len(clean_data)
        logger.info(f"📌 {key.upper()}: {updated_counts[key]} IOCs atualizados via MySQL.")

    with open(os.path.join(CACHE_FOLDER, "last_update.txt"), "w") as file:
        file.write(datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S'))

    cursor.close()
    db.close()
    return updated_counts

def fetch_iocs_via_api():
    settings = db_system.get_settings()
    url = settings.get('misp_url', '')
    api_key = settings.get('misp_api_key', '')
    verify_ssl = settings.get('misp_verify_ssl', 'false').lower() == 'true'

    if not url or not api_key:
        logger.warning("MISP API URL ou Key não configurada. Não foi possível sincronizar via API.")
        return {}

    logger.info("[INFO] Atualizando IOCs via API REST do MISP...")
    misp = PyMISP(url, api_key, ssl=verify_ssl, timeout=30)

    type_mapping = {
        "ips": ['ip-src', 'ip-dst'],
        "domains": ['domain'],
        "urls": ['url'],
        "filehashs": ['md5', 'sha1', 'sha256']
    }

    updated_counts = {}

    for key, type_list in type_mapping.items():
        try:
            res = misp.search(controller='attributes', type_attribute=type_list, pythonify=True, limit=5000)
            raw_data = []
            for attr in res:
                raw_data.append({
                    'value': attr.value,
                    'comment': attr.comment,
                    'timestamp': attr.timestamp.timestamp() if hasattr(attr, 'timestamp') and attr.timestamp else None,
                    'threat_level_id': '2',
                    'info': 'Importado via API MISP',
                    'event_id': str(attr.event_id) if hasattr(attr, 'event_id') else ''
                })

            clean_data = filter_ioc_data(raw_data, key)
            temp_file = CACHE_FILES[key] + ".tmp"
            with open(temp_file, "w", encoding="utf-8") as file:
                json.dump(clean_data, file)

            os.replace(temp_file, CACHE_FILES[key])
            updated_counts[key] = len(clean_data)
            logger.info(f"📌 {key.upper()}: {updated_counts[key]} IOCs atualizados via API.")
        except Exception as e:
            logger.error(f"Erro ao buscar {key} via API MISP: {e}")

    with open(os.path.join(CACHE_FOLDER, "last_update.txt"), "w") as file:
        file.write(datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S'))

    return updated_counts

def sync_iocs():
    mode = db_system.get_setting('misp_read_mode', 'database')
    try:
        if mode == 'api':
            return fetch_iocs_via_api()
        else:
            return fetch_iocs_via_mysql()
    except Exception as e:
        logger.error(f"Erro durante sync de IOCs: {e}")
        # Tenta fallback para MySQL se o erro foi no modo api
        if mode == 'api':
            logger.info("Tentando fallback para MySQL...")
            try:
                return fetch_iocs_via_mysql()
            except Exception as e2:
                logger.error(f"Fallback MySQL também falhou: {e2}")
        return {}

# --- Escrita / Adição de Atributos no MISP via API ---

def get_or_create_default_event(misp):
    """Busca ou cria um evento mensal padrão para agregar os IOCs inseridos pelo Cortex"""
    event_title = f"Cortex SOC Ingestion - {datetime.datetime.now().strftime('%Y-%m')}"
    try:
        events = misp.search(controller='events', eventinfo=event_title, limit=1)
        if events:
            return events[0]['Event']['id']
    except Exception:
        pass

    # Cria novo evento se não encontrado
    event = MISPEvent()
    event.info = event_title
    event.distribution = 1 # This community only
    event.threat_level_id = 2 # Medium
    event.analysis = 1 # Ongoing
    created = misp.add_event(event)
    if 'Event' in created:
        return created['Event']['id']
    raise Exception("Falha ao criar evento padrão no MISP.")

def extract_misp_error(res):
    if not isinstance(res, dict):
        return str(res)
    if 'errors' in res:
        err = res['errors']
        if isinstance(err, (tuple, list)) and len(err) > 1 and isinstance(err[1], dict):
            inner_errors = err[1].get('errors')
            if isinstance(inner_errors, dict):
                messages = []
                for field, msgs in inner_errors.items():
                    if isinstance(msgs, list):
                        messages.append(f"{field}: {', '.join(str(m) for m in msgs)}")
                    else:
                        messages.append(f"{field}: {msgs}")
                if messages:
                    return "; ".join(messages)
            if 'message' in err[1]:
                return str(err[1]['message'])
        elif isinstance(err, dict):
            messages = []
            for field, msgs in err.items():
                if isinstance(msgs, list):
                    messages.append(f"{field}: {', '.join(str(m) for m in msgs)}")
                else:
                    messages.append(f"{field}: {msgs}")
            if messages:
                return "; ".join(messages)
        return str(err)
    return "Erro desconhecido retornado pelo MISP"

def add_ioc_attribute(category, attr_type, distribution, value, comment="", event_id=None):
    """
    Adiciona um novo atributo no MISP estritamente via API REST.
    Suporta múltiplos valores separados por linha.
    Retorna: (success: bool, message: str, event_id: str, added_values: list)
    """
    settings = db_system.get_settings()
    url = settings.get('misp_url', '')
    api_key = settings.get('misp_api_key', '')
    verify_ssl = settings.get('misp_verify_ssl', 'false').lower() == 'true'

    if not url or not api_key:
        return False, "A URL e a Chave de API do MISP devem estar configuradas no Painel de Configurações.", None, []

    try:
        misp = PyMISP(url, api_key, ssl=verify_ssl, timeout=15)
        
        target_event_id = event_id
        if not target_event_id:
            target_event_id = get_or_create_default_event(misp)

        values = [v.strip() for v in value.strip().split('\n') if v.strip()]
        if not values:
            return False, "Nenhum valor válido fornecido.", target_event_id, []

        dist_val = int(distribution) if distribution.isdigit() else 5

        added_values = []
        failed_details = []

        for val in values:
            attr = MISPAttribute()
            attr.category = category
            attr.type = attr_type
            attr.value = val
            attr.comment = comment
            if dist_val != 5: # Se não for inherit
                attr.distribution = dist_val

            res = misp.add_attribute(target_event_id, attr)
            if res and isinstance(res, dict) and 'Attribute' in res:
                added_values.append(val)
            else:
                err_msg = extract_misp_error(res)
                failed_details.append(f"{val} ({err_msg})")

        if not added_values:
            return False, f"Nenhum IOC pôde ser adicionado ao evento #{target_event_id}. Motivo: {'; '.join(failed_details)}", target_event_id, []

        if failed_details:
            return True, f"{len(added_values)} IOC(s) adicionado(s) com sucesso ao evento #{target_event_id}! Porém houveram falhas em: {'; '.join(failed_details)}", target_event_id, added_values

        return True, f"{len(added_values)} IOC(s) adicionado(s) com sucesso ao evento #{target_event_id} no MISP!", target_event_id, added_values

    except Exception as e:
        logger.error(f"Erro ao adicionar atributo no MISP via API: {e}")
        return False, f"Falha na comunicação com o MISP: {str(e)}", None, []

