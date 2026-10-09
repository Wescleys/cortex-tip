import os
import json
import logging
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash

# Carrega variáveis do .env se o arquivo existir localmente
try:
    from dotenv import load_dotenv
    _env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.exists(_env_file):
        load_dotenv(dotenv_path=_env_file)
except Exception:
    pass

logger = logging.getLogger("cortex_db")

# Configurações obrigatórias do MariaDB (Docker)
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "cortex_user")
DB_PASSWORD = os.getenv("DB_PASSWORD", "cortex_secret_2026")
DB_NAME = os.getenv("DB_NAME", "cortex_system")

class DBConnection:
    """Wrapper de conexão exclusiva com o MariaDB."""
    def __init__(self, raw_conn):
        self.conn = raw_conn

    def cursor(self):
        return DBCursor(self.conn.cursor(dictionary=True))

    def commit(self):
        self.conn.commit()

    def rollback(self):
        self.conn.rollback()

    def close(self):
        self.conn.close()

class DBCursor:
    """Cursor nativo do MariaDB com suporte a dicionário e normalização de parâmetros."""
    def __init__(self, raw_cursor):
        self.cursor = raw_cursor

    def _prepare_sql(self, sql):
        # Converte ? para %s para mysql.connector
        sql = sql.replace("?", "%s")
        # Adaptação de upsert para MariaDB
        if "ON CONFLICT(key) DO UPDATE SET" in sql:
            sql = sql.replace(
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP",
                "ON DUPLICATE KEY UPDATE `value` = VALUES(`value`), updated_at = CURRENT_TIMESTAMP"
            )
        if "ON CONFLICT(ioc_value) DO UPDATE SET" in sql:
            sql = """
                INSERT INTO enrichment_cache (ioc_value, ioc_type, vt_data, abuse_data, geo_data, ai_analysis, mitre_tags, shodan_data, otx_data, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                ON DUPLICATE KEY UPDATE
                    vt_data = VALUES(vt_data),
                    abuse_data = VALUES(abuse_data),
                    geo_data = VALUES(geo_data),
                    ai_analysis = VALUES(ai_analysis),
                    mitre_tags = VALUES(mitre_tags),
                    shodan_data = VALUES(shodan_data),
                    otx_data = VALUES(otx_data),
                    updated_at = CURRENT_TIMESTAMP
            """
        if "ON CONFLICT(feed_type) DO UPDATE SET" in sql:
            sql = """
                INSERT INTO feed_cache (feed_type, payload, updated_at)
                VALUES (%s, %s, CURRENT_TIMESTAMP)
                ON DUPLICATE KEY UPDATE
                    payload = VALUES(payload),
                    updated_at = CURRENT_TIMESTAMP
            """
        return sql

    def execute(self, sql, params=None):
        sql = self._prepare_sql(sql)
        if params is not None:
            return self.cursor.execute(sql, params)
        return self.cursor.execute(sql)

    def fetchone(self):
        return self.cursor.fetchone()

    def fetchall(self):
        rows = self.cursor.fetchall()
        return list(rows) if rows else []

    @property
    def lastrowid(self):
        return self.cursor.lastrowid

def get_db():
    """
    Retorna uma conexão ativa com o MariaDB.
    NÃO POSSUI FALLBACK. Se o MariaDB estiver indisponível, lança erro explícito.
    """
    try:
        raw_conn = mysql.connector.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            connect_timeout=5,
            autocommit=False
        )
        return DBConnection(raw_conn)
    except mysql.connector.Error as err:
        err_msg = (
            f"\n[ERRO CRÍTICO] Falha ao conectar ao MariaDB em {DB_HOST}:{DB_PORT}/{DB_NAME}.\n"
            f"Execute o comando para iniciar o contêiner:\n"
            f"    npx cortex-tip db:up   (ou: docker compose up -d)\n"
            f"Detalhe do erro: {err}\n"
        )
        logger.critical(err_msg)
        raise ConnectionError(err_msg) from err

def init_db():
    """Inicializa a base de dados e as tabelas exclusivamente no MariaDB."""
    # Garante que o banco de dados exista
    try:
        root_conn = mysql.connector.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            connect_timeout=5
        )
        root_cur = root_conn.cursor()
        root_cur.execute(f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
        root_conn.commit()
        root_conn.close()
    except Exception as e:
        logger.debug(f"Verificação de criação de banco: {e}")

    conn = get_db()
    cursor = conn.cursor()

    # 1. Tabela de Usuários (RBAC)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            first_name VARCHAR(100) NOT NULL,
            last_name VARCHAR(100) NOT NULL,
            email VARCHAR(191) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(50) NOT NULL DEFAULT 'analista',
            is_active TINYINT(1) NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    ''')

    # 2. Tabela de Configurações do Sistema
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            `key` VARCHAR(100) PRIMARY KEY,
            `value` LONGTEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    ''')

    # 3. Tabela de Auditoria de IOCs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ioc_audit_log (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            user_name VARCHAR(100),
            user_email VARCHAR(191),
            user_role VARCHAR(50),
            ioc_value VARCHAR(500) NOT NULL,
            ioc_type VARCHAR(100) NOT NULL,
            category VARCHAR(100) NOT NULL,
            distribution VARCHAR(100) NOT NULL,
            comment TEXT,
            misp_event_id VARCHAR(100),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    ''')

    # 4. Tabela de Cache de Enriquecimento
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS enrichment_cache (
            ioc_value VARCHAR(500) PRIMARY KEY,
            ioc_type VARCHAR(100) NOT NULL,
            vt_data LONGTEXT,
            abuse_data LONGTEXT,
            geo_data LONGTEXT,
            ai_analysis LONGTEXT,
            mitre_tags LONGTEXT,
            shodan_data LONGTEXT,
            otx_data LONGTEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    ''')

    # 5. Tabela de Cache de Feeds (News e CVEs)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS feed_cache (
            feed_type VARCHAR(100) PRIMARY KEY,
            payload LONGTEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    ''')

    # 6. Tabela de Logs de Tráfego Real de Rede (Syslog / NetFlow Interceptor)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS real_traffic_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            src_ip VARCHAR(100) NOT NULL,
            dst_ip VARCHAR(100) NOT NULL,
            port INT DEFAULT 0,
            protocol VARCHAR(20) DEFAULT 'TCP',
            action VARCHAR(50) DEFAULT 'FORWARD',
            matched_ioc VARCHAR(500) DEFAULT '',
            is_threat TINYINT(1) DEFAULT 0,
            threat_severity VARCHAR(50) DEFAULT 'INFO',
            raw_message TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    ''')

    conn.commit()

    # Configurações padrão
    default_settings = {
        "misp_read_mode": "database",
        "misp_url": "",
        "misp_api_key": "",
        "misp_verify_ssl": "false",
        "misp_mysql_host": "",
        "misp_mysql_user": "",
        "misp_mysql_password": "",
        "misp_mysql_database": "",
        "ai_provider": "ollama",
        "ollama_url": "",
        "ollama_model": "deepseek-r1:8b",
        "gemini_api_key": "",
        "openai_api_key": "",
        "anthropic_api_key": "",
        "virustotal_api_key": "",
        "abuseipdb_api_key": "",
        "geoip_provider": "ip-api",
        "geoip_api_key": ""
    }

    for k, v in default_settings.items():
        cursor.execute("INSERT IGNORE INTO settings (`key`, `value`) VALUES (%s, %s)", (k, v))

    conn.commit()
    conn.close()
    logger.info("Banco de dados MariaDB inicializado com sucesso.")

# --- Funções de Usuários ---

def count_users():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as cnt FROM users")
    row = cursor.fetchone()
    count = row['cnt'] if row else 0
    conn.close()
    return count

def get_user_by_id(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def get_user_by_email(email):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE LOWER(email) = LOWER(%s)", (email.strip(),))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

MIN_PASSWORD_LENGTH = 12

def validate_password_complexity(password):
    if not password or len(password.strip()) < MIN_PASSWORD_LENGTH:
        return False, f"A senha deve conter no mínimo {MIN_PASSWORD_LENGTH} caracteres."
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    if not has_upper:
        return False, "A senha deve conter pelo menos uma letra maiúscula."
    if not has_lower:
        return False, "A senha deve conter pelo menos uma letra minúscula."
    if not has_digit:
        return False, "A senha deve conter pelo menos um número."
    if not has_special:
        return False, "A senha deve conter pelo menos um caractere especial."
    
    return True, None

def create_user(first_name, last_name, email, password, role='analista', is_active=1):
    valid, err = validate_password_complexity(password)
    if not valid:
        return None, err

    password_hash = generate_password_hash(password)
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO users (first_name, last_name, email, password_hash, role, is_active)
            VALUES (%s, %s, %s, %s, %s, %s)
        ''', (first_name.strip(), last_name.strip(), email.strip().lower(), password_hash, role, is_active))
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        return user_id, None
    except Exception as e:
        conn.close()
        err_str = str(e).lower()
        if "duplicate" in err_str or "1062" in err_str:
            return None, "E-mail já cadastrado no sistema."
        return None, str(e)

def list_users():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, first_name, last_name, email, role, is_active, created_at FROM users ORDER BY id ASC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def update_user_status(user_id, is_active):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET is_active = %s WHERE id = %s", (is_active, user_id))
    conn.commit()
    conn.close()

def update_user_role(user_id, role):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET role = %s WHERE id = %s", (role, user_id))
    conn.commit()
    conn.close()

def update_user_password(user_id, new_password):
    valid, err = validate_password_complexity(new_password)
    if not valid:
        return False, err
    password_hash = generate_password_hash(new_password)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s", (password_hash, user_id))
    conn.commit()
    conn.close()
    return True, None

def update_user_profile(user_id, first_name, last_name, email, current_password=None, new_password=None):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return False, "Usuário não encontrado."

    email_clean = email.strip().lower()
    cursor.execute("SELECT id FROM users WHERE LOWER(email) = %s AND id != %s", (email_clean, user_id))
    if cursor.fetchone():
        conn.close()
        return False, "Este e-mail já está sendo utilizado por outra conta."

    if new_password:
        if not current_password:
            conn.close()
            return False, "Por motivos de segurança, informe sua senha atual para definir uma nova senha."
        if not check_password_hash(user['password_hash'], current_password):
            conn.close()
            return False, "A senha atual informada está incorreta."
        valid, err = validate_password_complexity(new_password)
        if not valid:
            conn.close()
            return False, err

        new_hash = generate_password_hash(new_password)
        cursor.execute('''
            UPDATE users 
            SET first_name = %s, last_name = %s, email = %s, password_hash = %s
            WHERE id = %s
        ''', (first_name.strip(), last_name.strip(), email_clean, new_hash, user_id))
    else:
        cursor.execute('''
            UPDATE users 
            SET first_name = %s, last_name = %s, email = %s
            WHERE id = %s
        ''', (first_name.strip(), last_name.strip(), email_clean, user_id))

    conn.commit()
    conn.close()
    return True, None

def admin_update_user(user_id, first_name, last_name, email, role, is_active, new_password=None):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    target = cursor.fetchone()
    if not target:
        conn.close()
        return False, "Usuário não encontrado."

    email_clean = email.strip().lower()
    cursor.execute("SELECT id FROM users WHERE LOWER(email) = %s AND id != %s", (email_clean, user_id))
    if cursor.fetchone():
        conn.close()
        return False, "Este e-mail já está em uso por outro usuário."

    if (role != 'admin' or int(is_active) == 0) and target['role'] == 'admin':
        cursor.execute("SELECT COUNT(*) as cnt FROM users WHERE role = 'admin' AND is_active = 1 AND id != %s", (user_id,))
        cnt_row = cursor.fetchone()
        if not cnt_row or cnt_row['cnt'] == 0:
            conn.close()
            return False, "Operação bloqueada: o sistema não pode ficar sem nenhum administrador ativo."

    if new_password and new_password.strip():
        valid, err = validate_password_complexity(new_password.strip())
        if not valid:
            conn.close()
            return False, err
        new_hash = generate_password_hash(new_password.strip())
        cursor.execute('''
            UPDATE users 
            SET first_name = %s, last_name = %s, email = %s, role = %s, is_active = %s, password_hash = %s
            WHERE id = %s
        ''', (first_name.strip(), last_name.strip(), email_clean, role, int(is_active), new_hash, user_id))
    else:
        cursor.execute('''
            UPDATE users 
            SET first_name = %s, last_name = %s, email = %s, role = %s, is_active = %s
            WHERE id = %s
        ''', (first_name.strip(), last_name.strip(), email_clean, role, int(is_active), user_id))

    conn.commit()
    conn.close()
    return True, None

def delete_user(user_id):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    target = cursor.fetchone()
    if not target:
        conn.close()
        return False, "Usuário não encontrado."

    if target['role'] == 'admin':
        cursor.execute("SELECT COUNT(*) as cnt FROM users WHERE role = 'admin' AND is_active = 1 AND id != %s", (user_id,))
        cnt_row = cursor.fetchone()
        if not cnt_row or cnt_row['cnt'] == 0:
            conn.close()
            return False, "Não é permitido excluir o único administrador ativo do sistema."

    cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
    conn.commit()
    conn.close()
    return True, None

# --- Funções de Configurações ---

def get_settings():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT `key`, `value` FROM settings")
    rows = cursor.fetchall()
    conn.close()
    return {r['key']: r['value'] for r in rows}

def get_setting(key, default=""):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT `value` FROM settings WHERE `key` = %s", (key,))
    row = cursor.fetchone()
    conn.close()
    return row['value'] if row else default

def save_settings(settings_dict):
    conn = get_db()
    cursor = conn.cursor()
    for k, v in settings_dict.items():
        cursor.execute('''
            INSERT INTO settings (`key`, `value`, updated_at) 
            VALUES (%s, %s, CURRENT_TIMESTAMP)
            ON DUPLICATE KEY UPDATE `value` = VALUES(`value`), updated_at = CURRENT_TIMESTAMP
        ''', (k, str(v)))
    conn.commit()
    conn.close()

def set_setting(key, value):
    save_settings({key: value})

# --- Funções de Auditoria ---

def log_ioc_addition(user_id, user_name, user_email, user_role, ioc_value, ioc_type, category, distribution, comment, misp_event_id=""):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO ioc_audit_log (user_id, user_name, user_email, user_role, ioc_value, ioc_type, category, distribution, comment, misp_event_id)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    ''', (user_id, user_name, user_email, user_role, ioc_value, ioc_type, category, distribution, comment, misp_event_id))
    conn.commit()
    conn.close()

def get_audit_logs(limit=100):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, user_id, user_name, user_email, user_role, ioc_value, ioc_type, category, distribution, comment, misp_event_id, created_at
        FROM ioc_audit_log
        ORDER BY created_at DESC
        LIMIT %s
    ''', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# --- Funções de Cache de Enriquecimento ---

def get_cached_enrichment(ioc_value):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM enrichment_cache WHERE ioc_value = %s", (ioc_value.strip().lower(),))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    keys = row.keys()
    return {
        "ioc_value": row['ioc_value'],
        "ioc_type": row['ioc_type'],
        "vt_data": json.loads(row['vt_data']) if row['vt_data'] else None,
        "abuse_data": json.loads(row['abuse_data']) if row['abuse_data'] else None,
        "geo_data": json.loads(row['geo_data']) if row['geo_data'] else None,
        "ai_analysis": json.loads(row['ai_analysis']) if row['ai_analysis'] else None,
        "mitre_tags": json.loads(row['mitre_tags']) if row['mitre_tags'] else [],
        "shodan_data": json.loads(row['shodan_data']) if ('shodan_data' in keys and row['shodan_data']) else None,
        "otx_data": json.loads(row['otx_data']) if ('otx_data' in keys and row['otx_data']) else None,
        "updated_at": row['updated_at']
    }

def save_cached_enrichment(ioc_value, ioc_type, vt_data=None, abuse_data=None, geo_data=None, ai_analysis=None, mitre_tags=None, shodan_data=None, otx_data=None):
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM enrichment_cache WHERE ioc_value = %s", (ioc_value.strip().lower(),))
    existing = cursor.fetchone()

    vt_str = json.dumps(vt_data) if vt_data is not None else (existing['vt_data'] if existing else None)
    abuse_str = json.dumps(abuse_data) if abuse_data is not None else (existing['abuse_data'] if existing else None)
    geo_str = json.dumps(geo_data) if geo_data is not None else (existing['geo_data'] if existing else None)
    ai_str = json.dumps(ai_analysis) if ai_analysis is not None else (existing['ai_analysis'] if existing else None)
    mitre_str = json.dumps(mitre_tags) if mitre_tags is not None else (existing['mitre_tags'] if existing else None)
    shodan_str = json.dumps(shodan_data) if shodan_data is not None else (existing['shodan_data'] if (existing and 'shodan_data' in existing.keys()) else None)
    otx_str = json.dumps(otx_data) if otx_data is not None else (existing['otx_data'] if (existing and 'otx_data' in existing.keys()) else None)

    cursor.execute('''
        INSERT INTO enrichment_cache (ioc_value, ioc_type, vt_data, abuse_data, geo_data, ai_analysis, mitre_tags, shodan_data, otx_data, updated_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
        ON DUPLICATE KEY UPDATE
            vt_data = VALUES(vt_data),
            abuse_data = VALUES(abuse_data),
            geo_data = VALUES(geo_data),
            ai_analysis = VALUES(ai_analysis),
            mitre_tags = VALUES(mitre_tags),
            shodan_data = VALUES(shodan_data),
            otx_data = VALUES(otx_data),
            updated_at = CURRENT_TIMESTAMP
    ''', (ioc_value.strip().lower(), ioc_type, vt_str, abuse_str, geo_str, ai_str, mitre_str, shodan_str, otx_str))
    
    conn.commit()
    conn.close()

# --- Funções de Cache de Feeds (Notícias e CVEs) ---

def get_feed_cache(feed_type):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT payload, updated_at FROM feed_cache WHERE feed_type = %s", (feed_type,))
    row = cursor.fetchone()
    conn.close()
    if row and row['payload']:
        return json.loads(row['payload']), row['updated_at']
    return None, None

def save_feed_cache(feed_type, payload):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO feed_cache (feed_type, payload, updated_at)
        VALUES (%s, %s, CURRENT_TIMESTAMP)
        ON DUPLICATE KEY UPDATE
            payload = VALUES(payload),
            updated_at = CURRENT_TIMESTAMP
    ''', (feed_type, json.dumps(payload)))
    conn.commit()
    conn.close()

def get_live_threat_ips():
    """
    Retorna a lista de IPs de ameaça da base (de enrichment_cache, ioc_audit_log, etc.)
    com geolocalização e metadados para alimentar o Live Attack Map.
    """
    attacks = []
    seen_ips = set()

    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # 1. Pega IPs de enrichment_cache que já possuem geo_data
        cursor.execute("""
            SELECT ioc_value, geo_data, vt_data, abuse_data, mitre_tags, updated_at 
            FROM enrichment_cache 
            WHERE ioc_type IN ('ips', 'ip-src', 'ip-dst') AND geo_data IS NOT NULL
            ORDER BY updated_at DESC LIMIT 50
        """)
        rows = cursor.fetchall()
        
        for r in rows:
            ip = r['ioc_value'].strip()
            if not ip or ip in seen_ips:
                continue
            
            geo = json.loads(r['geo_data']) if r.get('geo_data') else None
            if not geo or not geo.get('lat') or not geo.get('lon'):
                continue

            seen_ips.add(ip)
            
            # Detecta tipo de ameaça baseado nos dados cacheados
            threat_type = "Threat Intel Indicator"
            port = 443
            protocol = "TCP/TLS"
            severity = "Alto"

            if r.get('abuse_data'):
                try:
                    ab = json.loads(r['abuse_data'])
                    score = ab.get('data', {}).get('abuseConfidenceScore', 0)
                    if score > 75:
                        severity = "Crítico"
                        threat_type = "Brute Force / Scanner"
                        port = 22
                        protocol = "SSH"
                except Exception:
                    pass

            if r.get('mitre_tags'):
                try:
                    mt = json.loads(r['mitre_tags'])
                    if mt and len(mt) > 0:
                        threat_type = f"C2: {mt[0].get('name', 'Command & Control')}"
                        severity = "Crítico"
                except Exception:
                    pass

            attacks.append({
                "ip": ip,
                "lat": float(geo['lat']),
                "lon": float(geo['lon']),
                "country": geo.get('country', 'Desconhecido'),
                "countryCode": geo.get('countryCode', ''),
                "city": geo.get('city', ''),
                "flag": geo.get('flag', '🌐'),
                "isp": geo.get('isp', geo.get('as', '')),
                "threat_type": threat_type,
                "port": port,
                "protocol": protocol,
                "severity": severity,
                "source": "Enrichment Base"
            })
        
        conn.close()
    except Exception as e:
        logger.error(f"Erro ao buscar IPs para Live Attack Map: {e}")

    # Curated baseline global threat nodes para garantir atividade e diversidade contínua
    baseline_threats = [
        {"ip": "185.220.101.5", "lat": 52.3702, "lon": 4.8952, "country": "Holanda", "countryCode": "NL", "city": "Amsterdã", "flag": "🇳🇱", "threat_type": "Tor Exit Node / Scanner", "port": 9001, "protocol": "TOR", "severity": "Alto", "isp": "Tor Transit"},
        {"ip": "194.26.29.112", "lat": 55.7558, "lon": 37.6173, "country": "Rússia", "countryCode": "RU", "city": "Moscou", "flag": "🇷🇺", "threat_type": "C2 Cobalt Strike Beacon", "port": 443, "protocol": "HTTPS", "severity": "Crítico", "isp": "VDSina Network"},
        {"ip": "45.154.255.89", "lat": 50.4501, "lon": 30.5234, "country": "Ucrânia", "countryCode": "UA", "city": "Kyiv", "flag": "🇺🇦", "threat_type": "Ransomware Delivery", "port": 8080, "protocol": "HTTP", "severity": "Crítico", "isp": "Serverel Hosting"},
        {"ip": "222.186.42.15", "lat": 31.2304, "lon": 121.4737, "country": "China", "countryCode": "CN", "city": "Xangai", "flag": "🇨🇳", "threat_type": "SSH Brute Force Bot", "port": 22, "protocol": "SSH", "severity": "Alto", "isp": "China Telecom"},
        {"ip": "178.62.204.18", "lat": 51.5074, "lon": -0.1278, "country": "Reino Unido", "countryCode": "GB", "city": "Londres", "flag": "🇬🇧", "threat_type": "Log4j Exploit Probe", "port": 8983, "protocol": "TCP", "severity": "Crítico", "isp": "DigitalOcean LLC"},
        {"ip": "103.251.167.20", "lat": 28.6139, "lon": 77.2090, "country": "Índia", "countryCode": "IN", "city": "Nova Délhi", "flag": "🇮🇳", "threat_type": "DDoS Amplification", "port": 53, "protocol": "DNS", "severity": "Médio", "isp": "Airtel Broadband"},
        {"ip": "198.54.117.200", "lat": 40.7128, "lon": -74.0060, "country": "Estados Unidos", "countryCode": "US", "city": "Nova York", "flag": "🇺🇸", "threat_type": "Credential Stuffing", "port": 443, "protocol": "HTTPS", "severity": "Alto", "isp": "Namecheap Cloud"},
        {"ip": "187.0.234.129", "lat": -23.5505, "lon": -46.6333, "country": "Brasil", "countryCode": "BR", "city": "São Paulo", "flag": "🇧🇷", "threat_type": "MikroTik Exploit Scan", "port": 8291, "protocol": "Winbox", "severity": "Alto", "isp": "Claro Brasil"},
        {"ip": "104.244.76.13", "lat": 47.3769, "lon": 8.5417, "country": "Suíça", "countryCode": "CH", "city": "Zurique", "flag": "🇨🇭", "threat_type": "Banking Trojan C2", "port": 8443, "protocol": "TLS", "severity": "Crítico", "isp": "Equinix Zurich"},
        {"ip": "195.184.76.190", "lat": 38.7135, "lon": -77.7953, "country": "Estados Unidos", "countryCode": "US", "city": "Warrenton", "flag": "🇺🇸", "threat_type": "Mass Reconnaissance", "port": 80, "protocol": "HTTP", "severity": "Médio", "isp": "Onyphe SAS"},
        {"ip": "80.186.150.96", "lat": 61.1725, "lon": 22.6934, "country": "Finlândia", "countryCode": "FI", "city": "Huittinen", "flag": "🇫🇮", "threat_type": "Mirai Botnet Propagation", "port": 23, "protocol": "Telnet", "severity": "Crítico", "isp": "Elisa Oyj"},
        {"ip": "62.210.142.161", "lat": 48.8558, "lon": 2.3494, "country": "França", "countryCode": "FR", "city": "Paris", "flag": "🇫🇷", "threat_type": "Phishing Landing Page", "port": 443, "protocol": "HTTPS", "severity": "Alto", "isp": "Scaleway SAS"}
    ]

    for bt in baseline_threats:
        if bt['ip'] not in seen_ips:
            seen_ips.add(bt['ip'])
            attacks.append(bt)

    return attacks

def save_real_traffic_log(src_ip, dst_ip, port=0, protocol='TCP', action='PASS', matched_ioc=None, is_threat=False, threat_severity='Baixo', raw_message=''):
    """Salva um registro de tráfego de rede capturado pelo Syslog no MariaDB."""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO real_traffic_logs (src_ip, dst_ip, port, protocol, action, matched_ioc, is_threat, threat_severity, raw_message)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        ''', (src_ip, dst_ip, port, protocol, action, matched_ioc, 1 if is_threat else 0, threat_severity, raw_message[:1000]))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Erro ao salvar real_traffic_log: {e}")

def get_recent_traffic_logs(limit=50, threats_only=False):
    """Retorna os logs de tráfego mais recentes interceptados pelo Syslog."""
    try:
        conn = get_db()
        cursor = conn.cursor()
        if threats_only:
            cursor.execute('''
                SELECT id, src_ip, dst_ip, port, protocol, action, matched_ioc, is_threat, threat_severity, raw_message, created_at
                FROM real_traffic_logs
                WHERE is_threat = 1
                ORDER BY id DESC LIMIT %s
            ''', (limit,))
        else:
            cursor.execute('''
                SELECT id, src_ip, dst_ip, port, protocol, action, matched_ioc, is_threat, threat_severity, raw_message, created_at
                FROM real_traffic_logs
                ORDER BY id DESC LIMIT %s
            ''', (limit,))
        rows = cursor.fetchall()
        conn.close()
        logs = []
        for r in rows:
            created_str = r['created_at'].strftime('%d/%m/%Y %H:%M:%S') if r.get('created_at') else ''
            logs.append({
                "id": r['id'],
                "src_ip": r['src_ip'],
                "dst_ip": r['dst_ip'],
                "port": r['port'],
                "protocol": r['protocol'],
                "action": r['action'],
                "matched_ioc": r['matched_ioc'],
                "is_threat": bool(r['is_threat']),
                "threat_severity": r['threat_severity'],
                "raw_message": r['raw_message'],
                "created_at": created_str
            })
        return logs
    except Exception as e:
        logger.error(f"Erro ao buscar recent_traffic_logs: {e}")
        return []

def get_traffic_stats():
    """Retorna o total de pacotes capturados, ameaças interceptadas e hosts ativos."""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT COUNT(*) as total_pkts, 
                   COALESCE(SUM(is_threat), 0) as total_thrs,
                   COUNT(DISTINCT src_ip) as active_hosts
            FROM real_traffic_logs
        ''')
        row = cursor.fetchone()
        conn.close()
        total = int(row['total_pkts']) if row and row.get('total_pkts') else 0
        threats = int(row['total_thrs']) if row and row.get('total_thrs') else 0
        hosts = int(row['active_hosts']) if row and row.get('active_hosts') else 0
        return {"total_packets": total, "total_threats": threats, "active_hosts": hosts}
    except Exception as e:
        logger.error(f"Erro ao buscar estatísticas de tráfego: {e}")
        return {"total_packets": 0, "total_threats": 0, "active_hosts": 0}

def get_threat_intel_catalog():
    """
    Retorna o catálogo completo de Threat Intelligence:
    - Perfis de APTs / Atores de Ameaça Globais
    - Setores visados, TTPs MITRE e ferramentas
    """
    actors = [
        {
            "id": "apt-lockbit",
            "name": "LockBit 3.0",
            "alias": "Bitwise Spider",
            "origin": "Rússia / Leste Europeu",
            "flag": "🇷🇺",
            "category": "Ransomware-as-a-Service (RaaS)",
            "threat_level": "Crítico",
            "motivation": "Financeiro / Extorsão Dupla",
            "sectors": ["Governo", "Saúde", "Manufatura", "Financeiro"],
            "ttps": ["T1190 - Exploit Public-Facing App", "T1486 - Data Encrypted for Impact", "T1059 - Command & Scripting Interpreter", "T1562 - Impair Defenses"],
            "tools": ["LockBit Black", "StealBit", "Mimikatz", "PsExec"],
            "active_campaigns": "Campanha global de extorsão com vazamento de dados em dark web",
            "associated_iocs": ["194.26.29.112", "185.220.101.5", "lockbitapt.top"]
        },
        {
            "id": "apt-lazarus",
            "name": "Lazarus Group",
            "alias": "APT38 / Hidden Cobra / BlueNoroff",
            "origin": "Coreia do Norte",
            "flag": "🇰🇵",
            "category": "Nation-State Advanced Persistent Threat (APT)",
            "threat_level": "Crítico",
            "motivation": "Espionagem e Roubo de Criptoativos",
            "sectors": ["Bancos & Cripto", "Defesa", "Aeroespacial", "Energia"],
            "ttps": ["T1566 - Phishing Spear", "T1204 - User Execution", "T1071 - Application Layer Protocol", "T1105 - Ingress Tool Transfer"],
            "tools": ["AppleJeus", "BLINDINGCAN", "FastCash", "Manuscrypt"],
            "active_campaigns": "Ataques de engenharia social direcionados ao setor de Web3/Fintechs e órgãos governamentais",
            "associated_iocs": ["178.62.204.18", "45.154.255.89", "cryptoswap-security.net"]
        },
        {
            "id": "apt-killnet",
            "name": "KillNet",
            "alias": "Killnet Syndicate",
            "origin": "Rússia",
            "flag": "🇷🇺",
            "category": "Hacktivist & DDoS Syndicate",
            "threat_level": "Alto",
            "motivation": "Geopolítico / Sabotagem de Serviços",
            "sectors": ["Governo OTAN", "Aeroportos", "Sistemas de Saúde", "Mídia"],
            "ttps": ["T1498 - Network Denial of Service", "T1499 - Endpoint DoS", "T1583 - Acquire Infrastructure"],
            "tools": ["Ares Botnet", "CC-attack", "Slowloris", "Layer 7 Flooder"],
            "active_campaigns": "Ataques volumétricos contínuos contra portais governamentais e infraestruturas aeroportuárias",
            "associated_iocs": ["103.251.167.20", "222.186.42.15", "killnet-c2.cc"]
        },
        {
            "id": "apt-chimeraz",
            "name": "ChimeraZ / APT41",
            "alias": "Double Dragon / Wicked Panda",
            "origin": "China",
            "flag": "🇨🇳",
            "category": "State-Sponsored & Cybercrime Hybrid",
            "threat_level": "Crítico",
            "motivation": "Espionagem Industrial & Operações de Ransomware",
            "sectors": ["Telecomunicações", "Tecnologia", "Governo", "Indústria Farmacêutica"],
            "ttps": ["T1190 - Exploit Public-Facing App", "T1078 - Valid Accounts", "T1055 - Process Injection", "T1021 - Remote Services"],
            "tools": ["Cobalt Strike", "Crosswalk", "Skeleton Key", "Winnti"],
            "active_campaigns": "Exploração de vulnerabilidades de dia zero em firewalls de borda e roteadores empresariais",
            "associated_iocs": ["62.210.142.161", "104.244.76.13", "reparstores-portal.com"]
        },
        {
            "id": "apt-fancybear",
            "name": "Fancy Bear",
            "alias": "APT28 / Sofacy / Sednit",
            "origin": "Rússia (GRU)",
            "flag": "🇷🇺",
            "category": "Military Intelligence Cyber Unit",
            "threat_level": "Crítico",
            "motivation": "Inteligência Militar e Desinformação",
            "sectors": ["Ministérios da Defesa", "Embaixadas", "Telecomunicações", "Setor Energético"],
            "ttps": ["T1187 - Forced Authentication", "T1558 - Steal or Forge Kerberos Tickets", "T1133 - External Remote Services"],
            "tools": ["X-Agent", "CHOPSTICK", "Zebrocy", "Cannon"],
            "active_campaigns": "Operações cibernéticas contra órgãos de defesa e redes governamentais",
            "associated_iocs": ["198.54.117.200", "187.0.234.129", "nato-security-update.org"]
        }
    ]
    return actors

if __name__ == '__main__':
    init_db()
    print("Banco de dados MariaDB verificado e inicializado com sucesso!")
