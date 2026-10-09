"""
Cortex TIP — Live Syslog & NetFlow Traffic Interceptor
Escuta na porta UDP 1514 eventos de tráfego de Firewalls (Fortinet, pfSense, Palo Alto, Cisco, iptables)
e cruza em tempo real contra a base de IOCs do MISP/Cortex.
"""

import socket
import threading
import time
import re
import os
import json
import logging
from datetime import datetime

import db_system

logger = logging.getLogger("cortex_syslog")

SYSLOG_HOST = "0.0.0.0"
SYSLOG_PORT = int(os.environ.get("SYSLOG_PORT", 1514))
IOC_CACHE_FILE = os.path.join("cache", "misp_ips.json")

# Cache em memória para consulta ultrarrápida (O(1))
active_iocs = set()
last_ioc_load = 0

def load_ioc_blacklist():
    """Recarrega a lista de IPs maliciosos da base do Cortex/MISP a cada 60s"""
    global active_iocs, last_ioc_load
    now = time.time()
    if now - last_ioc_load < 60 and active_iocs:
        return active_iocs

    try:
        new_set = set()
        if os.path.exists(IOC_CACHE_FILE):
            with open(IOC_CACHE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                for item in data:
                    val = item.get("value") if isinstance(item, dict) else item
                    if val and isinstance(val, str):
                        new_set.add(val.strip().lower())
        
        # Adiciona também IPs das ameaças de base do Cortex
        for threat in db_system.get_live_threat_ips():
            if threat.get("ip"):
                new_set.add(threat["ip"].strip().lower())

        active_iocs = new_set
        last_ioc_load = now
        logger.info(f"[SYSLOG] {len(active_iocs)} IOCs carregados na memória para cruzamento em tempo real.")
    except Exception as e:
        logger.error(f"[SYSLOG] Erro ao recarregar IOCs: {e}")

    return active_iocs

def parse_syslog_message(raw_msg):
    """
    Parser universal de logs de firewall:
    Suporta Fortinet, pfSense, Palo Alto, Cisco ASA, iptables e RFC 3164/5424.
    """
    src_ip = None
    dst_ip = None
    port = 0
    proto = "TCP"
    action = "FORWARD"

    # 1. Padrão Fortinet / Sophos (chave=valor)
    if "srcip=" in raw_msg:
        m_src = re.search(r'srcip=([0-9a-fA-F\.\:]+)', raw_msg)
        m_dst = re.search(r'dstip=([0-9a-fA-F\.\:]+)', raw_msg)
        m_port = re.search(r'dstport=([0-9]+)', raw_msg)
        m_proto = re.search(r'proto(?:col)?=([A-Za-z0-9]+)', raw_msg)
        m_act = re.search(r'action=([A-Za-z0-9_-]+)', raw_msg)

        if m_src: src_ip = m_src.group(1)
        if m_dst: dst_ip = m_dst.group(1)
        if m_port: port = int(m_port.group(1))
        if m_proto: proto = m_proto.group(1).upper()
        if m_act: action = m_act.group(1).upper()

    # 2. Padrão iptables / Linux UFW (SRC=... DST=...)
    elif "SRC=" in raw_msg:
        m_src = re.search(r'SRC=([0-9a-fA-F\.\:]+)', raw_msg)
        m_dst = re.search(r'DST=([0-9a-fA-F\.\:]+)', raw_msg)
        m_port = re.search(r'DPT=([0-9]+)', raw_msg)
        m_proto = re.search(r'PROTO=([A-Za-z0-9]+)', raw_msg)

        if m_src: src_ip = m_src.group(1)
        if m_dst: dst_ip = m_dst.group(1)
        if m_port: port = int(m_port.group(1))
        if m_proto: proto = m_proto.group(1).upper()
        action = "DROP" if ("DROP" in raw_msg or "BLOCK" in raw_msg) else "PASS"

    # 3. Padrão genérico IPv4 (X.X.X.X -> Y.Y.Y.Y:PORT)
    else:
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', raw_msg)
        if len(ips) >= 2:
            src_ip = ips[0]
            dst_ip = ips[1]
            m_port = re.search(r':([0-9]{2,5})\b', raw_msg)
            if m_port:
                port = int(m_port.group(1))
        elif len(ips) == 1:
            src_ip = ips[0]
            dst_ip = "127.0.0.1"

    if not src_ip or not dst_ip:
        return None

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "port": port,
        "protocol": proto,
        "action": action,
        "raw_message": raw_msg
    }

def process_traffic_event(event):
    """Cruza o evento de tráfego com os IOCs conhecidos e salva no banco"""
    blacklist = load_ioc_blacklist()
    src = event["src_ip"].lower()
    dst = event["dst_ip"].lower()

    matched_ioc = ""
    is_threat = False
    threat_severity = "INFO"

    if dst in blacklist:
        matched_ioc = dst
        is_threat = True
        threat_severity = "CRÍTICO"
        logger.warning(f"🚨 [ALERTA DE TRÁFEGO REAL] Host interno {src} conectando ao IOC malicioso {dst} (Porta {event['port']})!")
    elif src in blacklist:
        matched_ioc = src
        is_threat = True
        threat_severity = "ALTO"
        logger.warning(f"🚨 [ALERTA DE TRÁFEGO REAL] Conexão de entrada do IOC malicioso {src} para o host {dst}!")

    db_system.save_real_traffic_log(
        src_ip=event["src_ip"],
        dst_ip=event["dst_ip"],
        port=event["port"],
        protocol=event["protocol"],
        action=event["action"],
        matched_ioc=matched_ioc,
        is_threat=is_threat,
        threat_severity=threat_severity,
        raw_message=event["raw_message"]
    )

def udp_syslog_server():
    """Loop principal do servidor Syslog UDP"""
    load_ioc_blacklist()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        sock.bind((SYSLOG_HOST, SYSLOG_PORT))
        logger.info(f"🛡️ [CORTEX SYSLOG] Coletor de tráfego real de rede ativo em UDP {SYSLOG_HOST}:{SYSLOG_PORT}")
    except Exception as e:
        logger.error(f"❌ [CORTEX SYSLOG] Falha ao vincular porta UDP {SYSLOG_PORT}: {e}")
        return

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            raw_msg = data.decode("utf-8", errors="replace").strip()
            parsed = parse_syslog_message(raw_msg)
            if parsed:
                process_traffic_event(parsed)
        except Exception as e:
            logger.error(f"[SYSLOG] Erro ao processar pacote UDP: {e}")
            time.sleep(0.1)

def simulate_background_telemetry():
    """
    Gera telemetria realista de fundo caso nenhum firewall esteja enviando logs no momento.
    Garante que o painel de tráfego mostre fluxos de rede ativos desde o primeiro instante.
    """
    import random
    time.sleep(5)
    
    known_threats = [
        ("62.210.142.161", 443, "HTTPS", "Phishing C2"),
        ("185.220.101.5", 9001, "TOR", "Tor Node Probe"),
        ("194.26.29.112", 443, "HTTPS", "Cobalt Strike Beacon"),
        ("222.186.42.15", 22, "SSH", "Brute Force Scanner"),
        ("187.0.234.129", 8291, "Winbox", "MikroTik Exploit Scan"),
        ("45.154.255.89", 8080, "HTTP", "Ransomware Delivery"),
        ("178.62.204.18", 8983, "TCP", "Log4j Remote Code Exec")
    ]

    internal_subnets = ["192.168.1.", "10.0.10.", "172.16.50."]

    while True:
        try:
            # Gera evento esporádico (a cada 4-10 segundos)
            time.sleep(random.randint(4, 9))
            
            # 35% de chance de bater contra um IOC malicioso conhecido
            if random.random() < 0.35:
                threat_ip, port, proto, desc = random.choice(known_threats)
                src = f"{random.choice(internal_subnets)}{random.randint(10, 240)}"
                action = random.choice(["DROP", "DENY", "BLOCK", "FORWARD"])
                raw_msg = f"<14>date={datetime.now().strftime('%Y-%m-%d')} time={datetime.now().strftime('%H:%M:%S')} devname=SOC-FW01 devid=FG100E type=traffic subtype=forward level=warning srcip={src} dstip={threat_ip} dstport={port} proto={proto} action={action} msg='Threat match: {desc}'"
                
                parsed = parse_syslog_message(raw_msg)
                if parsed:
                    process_traffic_event(parsed)
            else:
                # Tráfego rotineiro normal de rede (ex: DNS, CDN, HTTPS seguro)
                src = f"{random.choice(internal_subnets)}{random.randint(10, 240)}"
                normal_dst = f"{random.randint(100, 210)}.{random.randint(1, 250)}.{random.randint(1, 250)}.{random.randint(1, 250)}"
                port = random.choice([443, 80, 53, 123, 8443])
                proto = "UDP" if port in [53, 123] else "TCP"
                action = "ALLOW"
                raw_msg = f"<14>date={datetime.now().strftime('%Y-%m-%d')} time={datetime.now().strftime('%H:%M:%S')} devname=SOC-FW01 type=traffic srcip={src} dstip={normal_dst} dstport={port} proto={proto} action={action}"
                
                parsed = parse_syslog_message(raw_msg)
                if parsed:
                    process_traffic_event(parsed)
        except Exception:
            time.sleep(5)

def start_syslog_listener():
    """Inicia o servidor de escuta Syslog UDP real na porta 1514 (aguarda firewall físico)"""
    t_server = threading.Thread(target=udp_syslog_server, daemon=True)
    t_server.start()

    # Simulação desativada: o Cortex aguardará exclusivamente o tráfego real do firewall físico
    # t_sim = threading.Thread(target=simulate_background_telemetry, daemon=True)
    # t_sim.start()

    logger.info("🛡️ [CORTEX SYSLOG] Servidor UDP 1514 ativo. Aguardando pacotes reais de Firewall.")
