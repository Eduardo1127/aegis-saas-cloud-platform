#!/usr/bin/env python3
"""
AEGIS PHISHGUARD ENGINE - SIMULADOR DE PHISHING & INGENIERÍA SOCIAL
Author: Eduardo Mexquitic Rodriguez (EMR)
Version: 1.0 - Independent Engine for Human Risk Assessment
"""

import json
import datetime
import hashlib

PLANTILLAS_PHISHING = [
    {
        "id": "PAYROLL_UPDATE",
        "nombre": "Nómina y Actualización Bancaria",
        "asunto": "URGENTE: Actualización obligatoria de cuenta de depósito de nómina",
        "dificultad": "ALTA",
        "vector": "Ingeniería Social Financiera (T1566.002)",
        "riesgo_humano": "CRÍTICO"
    },
    {
        "id": "MICROSOFT_PASSWORD",
        "nombre": "Restablecimiento de Contraseña Microsoft 365",
        "asunto": "Alerta de Seguridad: Tu contraseña de correo expira en 2 horas",
        "dificultad": "MEDIA",
        "vector": "Robo de Credenciales de Acceso (T1566.001)",
        "riesgo_humano": "ALTO"
    },
    {
        "id": "SAT_INVOICE",
        "nombre": "Notificación de Factura / Buzón Tributario SAT",
        "asunto": "Notificación de Buzón Tributario: Requerimiento de Información Fiscal",
        "dificultad": "ALTA",
        "vector": "Suplantación Institucional (T1566.002)",
        "riesgo_humano": "CRÍTICO"
    }
]

def simulate_campaign(target_company: str, employee_count: int = 50, template_id: str = "PAYROLL_UPDATE") -> dict:
    """Simula una campaña de evaluación de vulnerabilidad humana (Phishing Ético)."""
    now_utc = datetime.datetime.utcnow().isoformat() + "Z"
    
    # Pick template
    template = next((t for t in PLANTILLAS_PHISHING if t["id"] == template_id), PLANTILLAS_PHISHING[0])
    
    # Calculate realistic vulnerability metrics based on deterministic seeds
    clicks = max(1, int(employee_count * 0.12)) # 12% click rate simulation
    compromised = max(0, int(clicks * 0.4))     # 4.8% credential input
    trained_automatically = employee_count - clicks
    
    score_vulnerabilidad = max(0, 100 - (compromised * 15 + clicks * 5))
    
    payload_raw = f"{target_company}-{employee_count}-{template_id}-{now_utc}".encode("utf-8")
    sha256_full = hashlib.sha256(payload_raw).hexdigest().upper()
    
    return {
        "status": "SUCCESS",
        "campaign_id": f"PHISH-CASE-{sha256_full[:8]}",
        "target_company": target_company,
        "employees_evaluated": employee_count,
        "template_used": template["nombre"],
        "asunto_simulado": template["asunto"],
        "vector_mitre": template["vector"],
        "metricas_riesgo_humano": {
            "correos_enviados": employee_count,
            "empleados_hicieron_clic": clicks,
            "empleados_ingresaron_datos": compromised,
            "empleados_capacitados_automaticamente": trained_automatically,
            "tasa_vulnerabilidad_humana": f"{round((compromised/employee_count)*100, 1)}%",
            "posture_score_humano": f"{score_vulnerabilidad}/100"
        },
        "sha256_custody_hash": sha256_full,
        "custody_stamp": f"SHA256-{sha256_full[:16]}",
        "timestamp_utc": now_utc,
        "signed_by": "Ing. Eduardo Mexquitic Rodríguez (EMR) - Aegis PhishGuard CISO Engine"
    }
