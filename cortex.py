from flask import Flask, jsonify, render_template, request, Response, redirect, url_for, flash, session, send_file
import json
import os
import threading
import time
import datetime
import logging
import ipaddress
import re
from werkzeug.security import check_password_hash

import db_system
import auth
import misp_service
import enrichment_service
import ai_service
import feed_service
import syslog_listener

# Configuração de Fuso Horário (sincroniza com o horário local do servidor)
if hasattr(time, 'tzset'):
    os.environ.setdefault('TZ', 'America/Sao_Paulo')
    try:
        time.tzset()
    except Exception:
        pass

# Inicializa banco MariaDB (Docker) para RBAC, Auditoria e Configurações
db_system.init_db()

# Inicializa coletor de Syslog UDP e telemetria de tráfego real
syslog_listener.start_syslog_listener()

# Diretório e configuração de logs
LOG_FOLDER = "logs"
os.makedirs(LOG_FOLDER, exist_ok=True)
log_file = os.path.join(LOG_FOLDER, "app.log")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(log_file, encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("cortex_app")

app = Flask(__name__, static_folder="static", template_folder="templates")
# Chave de sessão persistente para manter login ativo após recargas do servidor
persistent_secret = db_system.get_setting("flask_secret_key", "")
if not persistent_secret:
    import secrets
    persistent_secret = secrets.token_hex(32)
    db_system.set_setting("flask_secret_key", persistent_secret)
app.secret_key = persistent_secret

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_COOKIE_SECURE", "false").lower() == "true",
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(days=7)
)

CACHE_FOLDER = misp_service.CACHE_FOLDER
CACHE_FILES = misp_service.CACHE_FILES

# --- Injetor Global de Usuário, Logo e Token Anti-CSRF para os Templates ---
def get_or_create_csrf_token():
    if '_csrf_token' not in session:
        import secrets
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']

@app.context_processor
def inject_globals():
    logo = db_system.get_setting("platform_logo", "/static/cortex.png")
    return dict(
        current_user=auth.get_current_user(),
        csrf_token=get_or_create_csrf_token,
        platform_logo=logo
    )

@app.before_request
def security_and_routing_checks():
    # 1. Permite arquivos estáticos e requisições idempotentes seguras (GET, HEAD, OPTIONS)
    if request.path.startswith('/static'):
        return None

    # 2. Se não houver nenhum usuário cadastrado no sistema, redireciona estritamente para o /setup
    if auth.check_setup_required():
        if request.path != '/setup':
            return redirect(url_for('setup'))
    elif request.path == '/setup':
        # Se já existe admin configurado, impede acesso ao setup
        flash("O sistema já foi inicializado. Faça login.", "info")
        return redirect(url_for('login'))

    # 3. Validação de Token Anti-CSRF em métodos de escrita / alteração de estado
    if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
        token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
        if not token and request.is_json:
            token = (request.get_json(silent=True) or {}).get('csrf_token')

        expected = session.get('_csrf_token')
        import hmac
        if not expected or not token or not hmac.compare_digest(str(token), str(expected)):
            logger.warning(f"Tentativa de requisição bloqueada por falha no Token CSRF: {request.method} {request.path}")
            if request.path.startswith('/api/'):
                return jsonify({"success": False, "error": "Token de segurança CSRF inválido ou ausente."}), 403
            flash("Falha na validação de segurança da requisição (Token CSRF inválido ou expirado).", "error")
            return redirect(request.referrer or url_for('index'))

# --- Rotas de Autenticação e Setup ---

@app.route('/setup', methods=['GET', 'POST'])
def setup():
    if request.method == 'POST':
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not first_name or not last_name or not email or not password:
            flash("Todos os campos são obrigatórios.", "error")
            return render_template('setup.html')

        if password != confirm_password:
            flash("As senhas informadas não coincidem.", "error")
            return render_template('setup.html')

        valid_pwd, pwd_err = db_system.validate_password_complexity(password)
        if not valid_pwd:
            flash(pwd_err, "error")
            return render_template('setup.html')

        user_id, err = db_system.create_user(
            first_name=first_name,
            last_name=last_name,
            email=email,
            password=password,
            role='admin',
            is_active=1
        )

        if err:
            flash(f"Erro ao criar administrador: {err}", "error")
            return render_template('setup.html')

        # Auto-login após criação
        session['user_id'] = user_id
        flash("Administrador configurado com sucesso! Bem-vindo ao Cortex TIP.", "success")
        return redirect(url_for('index'))

    return render_template('setup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        next_url = request.form.get('next', '')

        user = db_system.get_user_by_email(email)
        if not user or not check_password_hash(user['password_hash'], password):
            flash("E-mail ou senha inválidos.", "error")
            return render_template('login.html')

        if not user['is_active']:
            flash("Esta conta de usuário foi desativada pelo administrador.", "error")
            return render_template('login.html')

        session['user_id'] = user['id']
        flash(f"Bem-vindo de volta, {user['first_name']}!", "success")

        if next_url and next_url.startswith('/'):
            return redirect(next_url)
        return redirect(url_for('index'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Sessão encerrada com sucesso.", "info")
    return redirect(url_for('index'))

# --- Rota de Perfil do Usuário ---

@app.route('/profile', methods=['GET', 'POST'])
@auth.login_required
def profile():
    user = auth.get_current_user()
    if request.method == 'POST':
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        email = request.form.get('email', '').strip()
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not first_name or not email:
            flash("Nome e e-mail são obrigatórios.", "error")
            return redirect(url_for('profile'))

        if new_password:
            if new_password != confirm_password:
                flash("A confirmação da nova senha não confere.", "error")
                return redirect(url_for('profile'))

        success, err = db_system.update_user_profile(
            user_id=user['id'],
            first_name=first_name,
            last_name=last_name,
            email=email,
            current_password=current_password if new_password else None,
            new_password=new_password if new_password else None
        )
        if not success:
            flash(err, "error")
        else:
            flash("Perfil atualizado com sucesso!", "success")
        return redirect(url_for('profile'))

    return render_template('profile.html', user=user)

# --- Rotas Administrativas (Admin Apenas) ---

@app.route('/users')
@auth.role_required(['admin'])
def users():
    all_users = db_system.list_users()
    return render_template('users.html', users=all_users)

@app.route('/users/create', methods=['POST'])
@auth.role_required(['admin'])
def create_user_route():
    first_name = request.form.get('first_name', '').strip()
    last_name = request.form.get('last_name', '').strip()
    email = request.form.get('email', '').strip()
    role = request.form.get('role', 'analista')
    password = request.form.get('password', '')

    if not first_name or not email or not password:
        flash("Preencha todos os campos obrigatórios.", "error")
        return redirect(url_for('users'))

    uid, err = db_system.create_user(first_name, last_name, email, password, role)
    if err:
        flash(f"Erro ao criar usuário: {err}", "error")
    else:
        flash(f"Usuário {first_name} {last_name} cadastrado como {role.upper()}!", "success")

    return redirect(url_for('users'))

@app.route('/users/edit/<int:user_id>', methods=['POST'])
@auth.role_required(['admin'])
def edit_user_route(user_id):
    first_name = request.form.get('first_name', '').strip()
    last_name = request.form.get('last_name', '').strip()
    email = request.form.get('email', '').strip()
    role = request.form.get('role', 'analista')
    is_active = request.form.get('is_active', '1')
    password = request.form.get('password', '').strip()

    if not first_name or not email:
        flash("Nome e e-mail são obrigatórios.", "error")
        return redirect(url_for('users'))

    success, err = db_system.admin_update_user(
        user_id=user_id,
        first_name=first_name,
        last_name=last_name,
        email=email,
        role=role,
        is_active=is_active,
        new_password=password if password else None
    )
    if not success:
        flash(f"Erro ao atualizar usuário: {err}", "error")
    else:
        flash(f"Usuário {first_name} {last_name} atualizado com sucesso!", "success")

    return redirect(url_for('users'))

@app.route('/users/delete/<int:user_id>', methods=['POST'])
@auth.role_required(['admin'])
def delete_user_route(user_id):
    current = auth.get_current_user()
    if current and current['id'] == user_id:
        flash("Você não pode excluir sua própria conta de administrador.", "error")
        return redirect(url_for('users'))

    success, err = db_system.delete_user(user_id)
    if not success:
        flash(f"Erro ao excluir usuário: {err}", "error")
    else:
        flash(f"Usuário #{user_id} excluído com sucesso do sistema.", "success")

    return redirect(url_for('users'))

@app.route('/users/toggle-status/<int:user_id>', methods=['POST'])
@auth.role_required(['admin'])
def toggle_user_status(user_id):
    current = auth.get_current_user()
    if current and current['id'] == user_id:
        flash("Você não pode desativar sua própria conta.", "error")
        return redirect(url_for('users'))

    target = db_system.get_user_by_id(user_id)
    if target:
        new_status = 0 if target['is_active'] else 1
        db_system.update_user_status(user_id, new_status)
        flash(f"Status do usuário alterado para {'Ativo' if new_status else 'Inativo'}.", "success")
    return redirect(url_for('users'))

@app.route('/settings')
@auth.role_required(['admin'])
def settings():
    current_settings = db_system.get_settings()
    return render_template('settings.html', settings=current_settings)

@app.route('/settings/save', methods=['POST'])
@auth.role_required(['admin'])
def save_settings_route():
    fields = [
        "misp_read_mode", "misp_url", "misp_api_key", "misp_verify_ssl",
        "misp_mysql_host", "misp_mysql_user", "misp_mysql_password", "misp_mysql_database",
        "ai_provider", "ollama_url", "ollama_model",
        "gemini_api_key", "openai_api_key", "anthropic_api_key",
        "virustotal_api_key", "abuseipdb_api_key",
        "geoip_provider", "geoip_api_key"
    ]
    new_settings = {}
    for f in fields:
        if f in request.form:
            new_settings[f] = request.form.get(f, '').strip()

    db_system.save_settings(new_settings)
    flash("Configurações atualizadas com sucesso!", "success")
    return redirect(url_for('settings'))

@app.route('/settings/logo/upload', methods=['POST'])
@auth.role_required(['admin'])
def upload_logo():
    # 1. Upload por arquivo
    if 'logo_file' in request.files and request.files['logo_file'].filename:
        file = request.files['logo_file']
        filename = file.filename
        ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
        if ext not in ('png', 'jpg', 'jpeg', 'svg', 'webp', 'gif'):
            flash("Formato de imagem inválido. Utilize PNG, JPG, SVG ou WEBP.", "error")
            return redirect(url_for('settings'))
        
        upload_folder = os.path.join(app.static_folder, "uploads")
        os.makedirs(upload_folder, exist_ok=True)
        saved_filename = f"custom_logo.{ext}"
        filepath = os.path.join(upload_folder, saved_filename)
        file.save(filepath)
        
        logo_url = f"/static/uploads/{saved_filename}?v={int(time.time())}"
        db_system.set_setting("platform_logo", logo_url)
        flash("Logotipo da plataforma atualizado com sucesso!", "success")
        return redirect(url_for('settings'))

    # 2. Upload por URL externa
    logo_url = request.form.get('logo_url', '').strip()
    if logo_url:
        db_system.set_setting("platform_logo", logo_url)
        flash("URL do logotipo atualizada com sucesso!", "success")
        return redirect(url_for('settings'))

    flash("Nenhum arquivo ou URL fornecido para a logo.", "error")
    return redirect(url_for('settings'))

@app.route('/settings/logo/reset', methods=['POST'])
@auth.role_required(['admin'])
def reset_logo():
    db_system.set_setting("platform_logo", "/static/cortex.png")
    flash("Logotipo restaurado para o padrão original da Cortex.", "info")
    return redirect(url_for('settings'))

# --- Rotas de Operações SOC (Analista ou Admin) ---

@app.route('/add-ioc', methods=['GET', 'POST'])
@auth.role_required(['admin', 'analista'])
def add_ioc():
    if request.method == 'POST':
        category = request.form.get('category', '').strip()
        attr_type = request.form.get('type', '').strip()
        distribution = request.form.get('distribution', '5').strip()
        value = request.form.get('value', '').strip()
        comment = request.form.get('comment', '').strip()

        if not category or not attr_type or not value:
            flash("Categoria, Tipo e Valor são obrigatórios.", "error")
            return redirect(url_for('add_ioc'))

        curr_user = auth.get_current_user()
        user_name = f"{curr_user['first_name']} {curr_user['last_name']}".strip() if curr_user else "Sistema"
        user_email = curr_user['email'] if curr_user else "N/A"
        user_role = curr_user['role'] if curr_user else "N/A"
        user_id = curr_user['id'] if curr_user else None

        # Adiciona a assinatura do analista no comentário
        author_signature = f"Por: {user_name}"
        if comment:
            if author_signature.lower() not in comment.lower():
                final_comment = f"{comment} - {author_signature}"
            else:
                final_comment = comment
        else:
            final_comment = author_signature

        # Inserção oficial via API REST do MISP
        success, message, target_event_id, added_values = misp_service.add_ioc_attribute(
            category=category,
            attr_type=attr_type,
            distribution=distribution,
            value=value,
            comment=final_comment
        )

        if success:
            # Registra na trilha de auditoria apenas os valores inseridos com sucesso
            for val in added_values:
                db_system.log_ioc_addition(
                    user_id=user_id,
                    user_name=user_name,
                    user_email=user_email,
                    user_role=user_role,
                    ioc_value=val,
                    ioc_type=attr_type,
                    category=category,
                    distribution=distribution,
                    comment=final_comment,
                    misp_event_id=str(target_event_id) if target_event_id else ""
                )
            flash(message, "success")
        else:
            flash(message, "error")

        return redirect(url_for('add_ioc'))

    return render_template(
        'add_ioc.html',
        categories=misp_service.MISP_CATEGORIES,
        types_by_category=misp_service.MISP_TYPES_BY_CATEGORY,
        distributions=misp_service.MISP_DISTRIBUTIONS
    )

@app.route('/audit')
@auth.role_required(['admin', 'analista'])
def audit():
    logs = db_system.get_audit_logs(limit=150)
    return render_template('audit.html', logs=logs)

# --- APIs de Teste e Auxiliares ---

@app.route('/api/test-misp-api', methods=['POST'])
@auth.role_required(['admin'])
def test_misp_api():
    data = request.get_json() or {}
    url = data.get('url', '').strip()
    key = data.get('key', '').strip()
    verify_ssl = bool(data.get('verify_ssl', False))
    success, msg = misp_service.test_api_connection(url, key, verify_ssl=verify_ssl)
    return jsonify({"success": success, "message": msg})

@app.route('/api/test-misp-mysql', methods=['POST'])
@auth.role_required(['admin'])
def test_misp_mysql():
    data = request.get_json() or {}
    success, msg = misp_service.test_mysql_connection(
        host=data.get('host', ''),
        user=data.get('user', ''),
        password=data.get('password', ''),
        database=data.get('database', '')
    )
    return jsonify({"success": success, "message": msg})

@app.route('/api/detect-ollama-models')
@auth.role_required(['admin'])
def detect_ollama():
    url = request.args.get('url', '').strip()
    if url:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname:
            return jsonify({"success": False, "models": [], "error": "Esquema inválido. Apenas http:// ou https:// são permitidos."}), 400
        # Previne SSRF contra serviços de metadados de nuvem e esquemas perigosos
        blocked_hosts = {'169.254.169.254', 'metadata.google.internal', 'instance-data', '100.100.100.200'}
        if parsed.hostname in blocked_hosts:
            return jsonify({"success": False, "models": [], "error": "Destino bloqueado por política de segurança (Anti-SSRF)."}), 400

    success, models, msg = ai_service.test_ollama_connection(url if url else None)
    return jsonify({
        "success": success,
        "models": models,
        "message": msg,
        "error": None if success else msg
    })

# --- APIs de Enriquecimento e Feeds (Públicas ou AJAX) ---

@app.route('/api/enrich')
def api_enrich():
    ioc_type = request.args.get('type', 'ips').strip()
    ioc_value = request.args.get('value', '').strip()
    comment = request.args.get('comment', '')

    if not ioc_value:
        return jsonify({"error": "Valor do IOC ausente."}), 400

    enriched = enrichment_service.enrich_ioc(ioc_value, ioc_type, comment)
    return jsonify(enriched)

@app.route('/api/ai-analyze', methods=['POST'])
@auth.login_required
def api_ai_analyze():
    data = request.get_json() or {}
    ioc_value = data.get('ioc_value', '').strip()
    ioc_type = data.get('ioc_type', 'ips').strip()
    misp_data = data.get('misp_data', {})

    if not ioc_value:
        return jsonify({"success": False, "error": "IOC não informado."}), 400

    # Busca enriquecimento prévio em cache ou executa enriquecimento imediato
    enrichment = db_system.get_cached_enrichment(ioc_value)
    if not enrichment:
        enrichment = enrichment_service.enrich_ioc(ioc_value, ioc_type, misp_data.get('desc', ''))
    res = ai_service.analyze_ioc_with_ai(ioc_value, ioc_type, misp_data, enrichment)
    return jsonify(res)

@app.route('/api/feed/news')
def api_news():
    return jsonify(feed_service.fetch_cyber_news())

@app.route('/api/feed/zero-days')
def api_zero_days():
    return jsonify(feed_service.fetch_zero_days())

@app.route('/api/live-attacks')
def api_live_attacks():
    attacks = db_system.get_live_threat_ips()
    countries = list(set(a['country'] for a in attacks if a.get('country')))
    
    # Extrai o IP real de acesso do operador/cliente
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if client_ip and ',' in client_ip:
        client_ip = client_ip.split(',')[0].strip()

    target = enrichment_service.resolve_target_location(client_ip)

    # 1. NEW THREATS DETECTED: Seleciona as 3 ameaças ativas mais críticas da lista
    sorted_threats = sorted(attacks, key=lambda x: 0 if x.get('severity') == 'Crítico' else 1)
    latest_threats = []
    for idx, t in enumerate(sorted_threats[:3]):
        latest_threats.append({
            "ip": t.get('ip', ''),
            "title": f"[{t.get('countryCode', 'IOC')}] {t.get('threat_type', 'Ameaça Ativa')}",
            "time": "Hoje" if idx == 0 else f"Há {idx * 15 + 10}m",
            "actor": t.get('isp') or t.get('threat_type') or "IOC Blacklist",
            "country": f"{t.get('country', 'Global')} {t.get('flag', '')}",
            "flag": t.get('flag', '🌐'),
            "severity": t.get('severity', 'CRÍTICO').upper(),
            "port": t.get('port', 0),
            "protocol": t.get('protocol', 'TCP'),
            "link": f"/search?query={t.get('ip', '')}"
        })
    latest_threat = latest_threats[0] if latest_threats else None

    # 2. TOP TARGETS: Agrupamento dinâmico dos países de origem/destino das ameaças
    from collections import Counter
    country_counts = Counter(a['country'] for a in attacks if a.get('country'))
    top_c = country_counts.most_common(5)
    max_c = top_c[0][1] if top_c else 1
    top_targets = []
    for idx, (cntry, cnt) in enumerate(top_c):
        flg = next((a.get('flag', '🌐') for a in attacks if a.get('country') == cntry), '🌐')
        top_targets.append({
            "rank": f"{idx+1:02d}",
            "country": cntry,
            "flag": flg,
            "mentions": cnt,
            "pct": int((cnt / max_c) * 100)
        })

    # 3. TOP ACTORS: Agrupamento dinâmico dos vetores/famílias de malware mais ativos
    threat_counts = Counter(a.get('threat_type', 'Malware Scan') for a in attacks if a.get('threat_type'))
    top_th = threat_counts.most_common(5)
    max_th = top_th[0][1] if top_th else 1
    top_actors = []
    for th_name, cnt in top_th:
        top_actors.append({
            "name": th_name,
            "pressure": min(98, max(55, int((cnt / max_th) * 95)))
        })

    # 4. TOP ATTACK VECTORS & TARGETED PORTS: Portas e Protocolos mais visados
    port_counts = Counter(f"{a.get('port', 80)}/{a.get('protocol', 'TCP')}" for a in attacks if a.get('port'))
    top_p = port_counts.most_common(4)
    max_p = top_p[0][1] if top_p else 1
    targeted_ports = []
    for p_name, cnt in top_p:
        targeted_ports.append({
            "target": p_name,
            "count": cnt,
            "pct": int((cnt / max_p) * 100)
        })
    if not targeted_ports:
        targeted_ports = [
            {"target": "443/HTTPS", "count": 12, "pct": 100},
            {"target": "22/SSH", "count": 9, "pct": 75},
            {"target": "8080/HTTP", "count": 6, "pct": 50},
            {"target": "3389/RDP", "count": 4, "pct": 33}
        ]

    # 5. CYBER INTELLIGENCE FEED: Alertas táticos em tempo real do catálogo CISA KEV
    raw_cves = feed_service.fetch_zero_days() or []
    cyber_feeds = []
    for cve in raw_cves[:3]:
        cyber_feeds.append({
            "actor": f"CISA KEV - {cve.get('vendor', 'Alerta')}",
            "desc": f"{cve.get('cve_id')}: {cve.get('name', '')[:85]}",
            "country": cve.get('product', 'Infraestrutura'),
            "time": cve.get('date_added', 'Recente')
        })
    if not cyber_feeds:
        cyber_feeds = [
            {"actor": "Threat Monitor", "desc": "Monitoramento em tempo real ativo.", "country": "Global", "time": "Agora"}
        ]

    # 6. ACTIVE DEFENSE POSTURE: Estatísticas do SOC
    traffic_stats = db_system.get_traffic_stats()
    defense_posture = {
        "total_iocs": len(attacks),
        "countries_count": len(countries),
        "threats_blocked": traffic_stats.get('total_threats', 0),
        "total_intercepted": traffic_stats.get('total_packets', 0)
    }

    return jsonify({
        "success": True,
        "target": target,
        "attacks": attacks,
        "top_targets": top_targets,
        "top_actors": top_actors,
        "targeted_ports": targeted_ports,
        "latest_threat": latest_threat,
        "latest_threats": latest_threats,
        "cyber_feeds": cyber_feeds,
        "defense_posture": defense_posture,
        "stats": {
            "total_threat_ips": len(attacks),
            "active_countries": len(countries),
            "threat_level": "ELEVADO" if len(attacks) >= 10 else "MODERADO"
        }
    })

@app.route('/threat-intelligence')
def threat_intelligence():
    user = auth.get_current_user()
    actors = db_system.get_threat_intel_catalog()
    raw_cves = feed_service.fetch_zero_days() or []
    attacks = db_system.get_live_threat_ips()
    traffic_stats = db_system.get_traffic_stats()
    
    stats = {
        "tracked_apts": len(actors),
        "zero_days_count": len(raw_cves),
        "active_iocs": len(attacks),
        "threats_blocked": traffic_stats.get('total_threats', 0)
    }
    
    return render_template(
        'threat_intelligence.html',
        user=user,
        actors=actors,
        zero_days=raw_cves[:25],
        threats=attacks,
        stats=stats
    )

@app.route('/network-traffic')
def network_traffic():
    user = auth.get_current_user()
    stats = db_system.get_traffic_stats()
    initial_logs = db_system.get_recent_traffic_logs(limit=100)
    syslog_port = os.environ.get("SYSLOG_PORT", 1514)
    return render_template(
        'network_traffic.html',
        current_user=user,
        stats=stats,
        initial_logs=initial_logs,
        syslog_port=syslog_port
    )

@app.route('/api/live-traffic')
def api_live_traffic():
    limit = min(int(request.args.get('limit', 50)), 200)
    threats_only = request.args.get('threats_only', 'false').lower() == 'true'
    logs = db_system.get_recent_traffic_logs(limit=limit, threats_only=threats_only)
    stats = db_system.get_traffic_stats()
    threats_count = stats.get('total_threats', 0)
    packets_count = stats.get('total_packets', 0)
    hosts_count = stats.get('active_hosts', 0)
    return jsonify({
        "success": True,
        "logs": logs,
        "recent_logs": logs,
        "stats": {
            "total_packets": packets_count,
            "threats_blocked": threats_count,
            "total_threats": threats_count,
            "active_hosts": hosts_count
        }
    })


# --- Rotas Principais Originais Preservadas ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/status', methods=['GET'])
def status():
    last_update = "Nunca"
    last_file = os.path.join(CACHE_FOLDER, "last_update.txt")
    if os.path.exists(last_file):
        with open(last_file, "r", encoding="utf-8") as f:
            last_update = f.read().strip()
            
    counts = {}
    for k, v in CACHE_FILES.items():
        if os.path.exists(v):
            try:
                with open(v, 'r', encoding="utf-8") as f:
                    counts[k] = len(json.load(f))
            except Exception:
                counts[k] = 0
        else:
            counts[k] = 0
            
    return jsonify({"status": f"Atualizado em: {last_update}", "ioc_counts": counts})

def detect_ioc_type(val):
    val = val.strip().lower()
    try:
        ipaddress.ip_address(val)
        return "ips"
    except ValueError:
        pass
    import re
    if re.match(r'^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$', val):
        return "filehashs"
    if val.startswith("http://") or val.startswith("https://"):
        return "urls"
    # Remove qualquer barra final para teste de domínio
    clean_val = val.rstrip('/')
    if "." in clean_val and " " not in clean_val and not clean_val.endswith(".") and not clean_val.startswith("."):
        return "domains"
    return None

@app.route('/search', methods=['GET'])
def search():
    raw_query = request.args.get('query', '').strip()
    if not raw_query:
        return render_template('search.html', results=None, query="", error=None)

    # Suporte a múltiplos IOCs separados por vírgula, ponto-e-vírgula ou quebras de linha
    import re
    from urllib.parse import urlparse

    sub_queries = [q.strip().lower() for q in re.split(r'[,;\n]+', raw_query) if q.strip()]
    if not sub_queries:
        return render_template('search.html', results=None, query="", error=None)

    # Carrega cache local MISP uma única vez
    local_caches = {}
    for key, file_path in CACHE_FILES.items():
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r', encoding="utf-8") as file:
                    local_caches[key] = json.load(file)
            except Exception as e:
                logger.error(f"Erro ao ler cache {key}: {e}")

    results = {}
    seen_values = set()

    for q in sub_queries:
        if len(q) < 3:
            continue
        
        q_clean = q.rstrip('/')
        detected_type = detect_ioc_type(q_clean)
        found_misp = False

        dom_from_url = None
        if detected_type == "urls":
            try:
                parsed = urlparse(q)
                dom_from_url = parsed.netloc.split(':')[0].lower()
            except Exception:
                pass

        for key, data in local_caches.items():
            matches = []

            # 1. IPs: EXCLUSIVAMENTE MATCH EXATO (evita que final 5 case com 50, 51, 52...)
            if detected_type == "ips":
                if key == "ips":
                    matches = [item for item in data if str(item.get('value', '')).strip().lower() == q_clean]

            # 2. Hashes: EXCLUSIVAMENTE MATCH EXATO
            elif detected_type == "filehashs":
                if key == "filehashs":
                    matches = [item for item in data if str(item.get('value', '')).strip().lower() == q_clean]

            # 3. URLs: Match exato de URL ou correlação com domínio base
            elif detected_type == "urls":
                if key == "urls":
                    matches = [item for item in data if str(item.get('value', '')).strip().lower().rstrip('/') == q_clean]
                elif key in ("domains", "ips") and dom_from_url:
                    matches = [item for item in data if str(item.get('value', '')).strip().lower() == dom_from_url]

            # 4. Domínios: Match exato prioritário OU subdomínio válido (*.dominio)
            elif detected_type == "domains":
                if key == "domains":
                    exact = [item for item in data if str(item.get('value', '')).strip().lower() == q_clean]
                    if exact:
                        matches = exact
                    else:
                        # Subdomínios estritos (termina com .dominio)
                        matches = [item for item in data if str(item.get('value', '')).strip().lower().endswith('.' + q_clean)]
                elif key == "urls":
                    # URLs hospedadas exatamente neste domínio
                    matches = [item for item in data if f"://{q_clean}/" in str(item.get('value', '')).lower() or str(item.get('value', '')).lower().startswith(f"http://{q_clean}") or str(item.get('value', '')).lower().startswith(f"https://{q_clean}")]

            # 5. Termo genérico / palavra-chave (ex: 'lockbit', 'emotet')
            else:
                generic_matches = [item for item in data if q_clean in str(item.get('value', '')).lower() or q_clean in str(item.get('desc', '')).lower()]
                matches = generic_matches[:10]  # Limite de segurança para não quebrar abas

            if matches:
                found_misp = True
                if key not in results:
                    results[key] = []
                for m in matches:
                    val = str(m.get('value', '')).lower()
                    if val not in seen_values:
                        seen_values.add(val)
                        results[key].append(m)

        if not found_misp:
            detected = detected_type or detect_ioc_type(q_clean)
            if detected:
                if detected not in results:
                    results[detected] = []
                if q_clean not in seen_values:
                    seen_values.add(q_clean)
                    results[detected].append({
                        "value": q_clean,
                        "desc": "Sem comentários",
                        "date": "Não catalogado",
                        "severity": "Indefinida",
                        "type": detected,
                        "is_unknown": True
                    })

    # Lista ordenada de todos os IOCs pesquisados para as Abas
    tabs_list = []
    for tipo, items in results.items():
        for item in items:
            tabs_list.append({
                "value": item['value'],
                "type": tipo
            })

    return render_template(
        'search.html',
        results=results,
        tabs_list=tabs_list,
        query=raw_query,
        date=datetime.datetime.now().strftime('%d/%m/%Y'),
        error=None if results else f"Nenhum indicador válido encontrado para '{raw_query}'."
    )

# --- Rotas de Texto Puro (Compatibilidade com Firewalls e SIEMs) ---
@app.route('/misp_ips.json', methods=['GET'])
def get_misp_ips(): return get_iocs_text("ips")

@app.route('/misp_urls.json', methods=['GET'])
def get_misp_urls(): return get_iocs_text("urls")

@app.route('/misp_dominios.json', methods=['GET'])
def get_misp_domains(): return get_iocs_text("domains")

@app.route('/misp_hashs.json', methods=['GET'])
def get_misp_hashs(): return get_iocs_text("filehashs")

def get_iocs_text(tipo):
    if tipo in CACHE_FILES and os.path.exists(CACHE_FILES[tipo]):
        try:
            with open(CACHE_FILES[tipo], 'r', encoding="utf-8") as file:
                data = json.load(file)
            
            unique_iocs = []
            seen = set()
            for item in data:
                val = item.get('value')
                if val and val not in seen:
                    seen.add(val)
                    unique_iocs.append(val)

            return Response("\n".join(unique_iocs), mimetype="text/plain")
        except Exception as e:
            logger.error(f"❌ Erro ao processar texto puro para {tipo}: {e}")
            return Response("Erro interno", status=500)
    return Response("Não encontrado", status=404)

# --- Thread Contínua de Atualização de Cache ---
def continuous_update():
    while True:
        try:
            logger.info("Iniciando ciclo contínuo de sincronização de IOCs...")
            misp_service.sync_iocs()
        except Exception as e:
            logger.error(f"Erro no ciclo contínuo: {e}")
        time.sleep(300) # 5 minutos

if __name__ == '__main__':
    # Inicia sincronização em background
    threading.Thread(target=continuous_update, daemon=True).start()
    port = int(os.environ.get("PORT", 80))
    app.run(debug=False, host='0.0.0.0', port=port)