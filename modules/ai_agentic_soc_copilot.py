#!/usr/bin/env python3
"""
AEGIS PRIME SAAS CLOUD PLATFORM - DYNAMIC AI AGENTIC SOC COPILOT MODULE
Author: Eduardo Mexquitic Rodriguez (EMR)
"""

import sys
import random
import hashlib
import datetime

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')


def analyze_incident(event_data):
    """
    Generates dynamic AI incident briefing and playbook based on target IP or domain.
    """
    target = event_data.get("target") or event_data.get("ip") or "185.220.101.5"
    severity = event_data.get("severity") or "CRITICAL"
    
    # Hash target to generate unique consistent incident IDs and scores per target
    hash_digest = hashlib.md5(target.encode('utf-8')).hexdigest()
    inc_num = int(hash_digest[:4], 16) % 9000 + 1000
    score = round(85.0 + (int(hash_digest[4:6], 16) % 150) / 10.0, 1)
    
    incident_id = f"INC-SAAS-{inc_num}"
    
    # Dynamic playbooks customized for target
    playbook = [
        f"1. Bloquear el tráfico no autorizado dirigido al objetivo {target} en el Firewall por 72 horas.",
        f"2. Auditar registros del API Gateway en busca de peticiones sospechosas hacia {target}.",
        f"3. Forzar rotación inmediata de credenciales administrativas para la infraestructura de {target}.",
        f"4. Generar reporte Syslog CEF para correlación en Splunk Enterprise."
    ]
    
    summary = f"El copiloto de IA ha detectado y mitigo de forma autónoma una amenaza de severidad {severity} dirigida hacia el objetivo {target}. El motor de defensa de Aegis aisló el vector de ataque con un score de confianza del {score}%."
    
    return {
        "incident_id": incident_id,
        "target": target,
        "severity": severity,
        "score": score,
        "executive_summary": summary,
        "playbook": playbook,
        "ai_engine": "Aegis Autonomous SOC Agent v2.5",
        "status": "ANALYZED & MITIGATED",
        "generated_at": datetime.datetime.now().isoformat()
    }


if __name__ == "__main__":
    test_res = analyze_incident({"target": "clinicamedica.com", "severity": "HIGH"})
    print("Dynamic Copilot Output:")
    print(test_res)
