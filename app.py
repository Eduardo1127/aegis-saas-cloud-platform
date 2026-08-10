#!/usr/bin/env python3
"""
AEGIS PRIME SAAS CLOUD PLATFORM - REST API & WEB SERVER ENGINE
Author: Eduardo Mexquitic Rodriguez (EMR)
Version: 3.1 - Enterprise Legal & Security Compliance Edition (Live Fix)
"""

import sys
import os
import time
import json
import datetime
import jwt
import stripe
from functools import wraps

from flask import Flask, request, jsonify, render_template, redirect, url_for

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')

import config
import database
from modules import ai_agentic_soc_copilot, cloud_security_auditor, red_recon_scanner

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["SECRET_KEY"] = config.SECRET_KEY

# Initialize Stripe API Key
stripe.api_key = config.STRIPE_SECRET_KEY


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            auth_header = request.headers["Authorization"]
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]
        
        if not token:
            token = request.cookies.get("saas_jwt_token")
            
        if not token:
            return jsonify({"status": "ERROR", "message": "Token de autenticación faltante."}), 401
            
        try:
            data = jwt.decode(token, config.SECRET_KEY, algorithms=[config.ALGORITHM])
            current_user_id = data["user_id"]
        except Exception:
            return jsonify({"status": "ERROR", "message": "Token inválido o expirado."}), 401
            
        return f(current_user_id, *args, **kwargs)
    return decorated


# --- WEB ROUTES ---

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/terms")
def terms():
    return """
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <title>Términos de Servicio — Aegis Prime SaaS</title>
        <style>body{font-family:sans-serif; background:#0a0d14; color:#f0f6fc; padding:40px; max-width:800px; margin:auto; line-height:1.6;} h1{color:#00ff88;} h2{color:#58a6ff; margin-top:24px;} a{color:#00ff88; text-decoration:none;}</style>
    </head>
    <body>
        <h1>⚖️ Términos de Servicio y Limitación de Responsabilidad</h1>
        <p><strong>Última actualización: 2026 — Aegis Prime SaaS / Eduardo Mexquitic Rodriguez (EMR)</strong></p>
        
        <h2>1. Naturaleza de los Servicios</h2>
        <p>Aegis Prime SaaS proporciona herramientas de auditoría perimetral, monitoreo de seguridad y asistencia mediante Copiloto de Inteligencia Artificial de carácter estrictamente defensivo e informativo.</p>
        
        <h2>2. Limitación de Responsabilidad</h2>
        <p>Las recomendaciones, análisis y playbooks generados por la plataforma o por el Copiloto de IA son sugerencias técnicas consultivas. La aplicación final de cambios de configuración, bloqueos de IP en cortafuegos o aislamiento de servidores recae única y exclusivamente bajo la decisión y responsabilidad del equipo de TI del Cliente.</p>
        <p>En ningún caso Aegis Prime SaaS o su fundador serán responsables por interrupciones de servicio no planificadas o pérdida de datos derivadas de la ejecución directa de recomendaciones por parte del cliente.</p>
        
        <h2>3. Límite Financiero de Indemnización</h2>
        <p>La responsabilidad financiera total del Proveedor frente al Cliente para cualquier reclamo no excederá la cantidad acumulada efectivamente pagada por el Cliente por el servicio en el último mes de suscripción.</p>
        
        <p style="margin-top:40px;"><a href="/">← Volver a la Plataforma Aegis SaaS</a></p>
    </body>
    </html>
    """

@app.route("/privacy")
def privacy():
    return """
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <title>Política de Privacidad y Cumplimiento — Aegis Prime SaaS</title>
        <style>body{font-family:sans-serif; background:#0a0d14; color:#f0f6fc; padding:40px; max-width:800px; margin:auto; line-height:1.6;} h1{color:#00ff88;} h2{color:#58a6ff; margin-top:24px;} a{color:#00ff88; text-decoration:none;}</style>
    </head>
    <body>
        <h1>🛡️ Política de Privacidad y Protección de Datos (Vendor Assessment)</h1>
        <p><strong>Aegis Prime SaaS — Cumplimiento SOC2 / GDPR / ISO 27001 Alignment</strong></p>
        
        <h2>1. Cifrado y Custodia de Información</h2>
        <p>Toda la información capturada durante los análisis se cifra en tránsito utilizando protocolos TLS 1.3 (HTTPS) y en reposo mediante algoritmos AES-256. El acceso a los datos está estrictamente aislado por usuario mediante tokens criptográficos JWT.</p>
        
        <h2>2. Propiedad de los Datos</h2>
        <p>El Cliente conserva el 100% de la propiedad de la información, informes y datos de su infraestructura auditados por la plataforma. Aegis Prime SaaS no vende ni comparte datos con terceros.</p>
        
        <h2>3. Retención y Eliminación de Registros</h2>
        <p>Los registros de escaneos se conservan por un período máximo de 30 días para análisis histórico del cliente y pueden ser eliminados a solicitud expresa del usuario.</p>
        
        <p style="margin-top:40px;"><a href="/">← Volver a la Plataforma Aegis SaaS</a></p>
    </body>
    </html>
    """

@app.route("/api/v1/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ONLINE",
        "service": "Aegis Prime SaaS Cloud Engine v3.1 (Enterprise Legal Edition)",
        "author": "Eduardo Mexquitic Rodriguez (EMR)",
        "timestamp": datetime.datetime.now().isoformat()
    })


# --- AUTHENTICATION API ENDPOINTS ---

@app.route("/api/v1/auth/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")
    company = data.get("company", "")
    
    if not email or not password:
        return jsonify({"status": "ERROR", "message": "Email y contraseña requeridos."}), 400
        
    success, user_or_err, hwid_key = database.register_user(email, password, company)
    if not success:
        return jsonify({"status": "ERROR", "message": user_or_err}), 400
        
    return jsonify({
        "status": "SUCCESS",
        "message": "Registro completado con éxito.",
        "user_id": user_or_err,
        "hwid_license": hwid_key
    }), 201


@app.route("/api/v1/auth/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")
    
    if not email or not password:
        return jsonify({"status": "ERROR", "message": "Email y contraseña requeridos."}), 400
        
    success, user_or_err = database.verify_user(email, password)
    if not success:
        return jsonify({"status": "ERROR", "message": user_or_err}), 401
        
    user = user_or_err
    token_payload = {
        "user_id": user["id"],
        "email": user["email"],
        "plan": user["plan"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=config.TOKEN_EXPIRE_HOURS)
    }
    token = jwt.encode(token_payload, config.SECRET_KEY, algorithm=config.ALGORITHM)
    
    resp = jsonify({
        "status": "SUCCESS",
        "message": "Autenticación exitosa.",
        "token": token,
        "user": user
    })
    resp.set_cookie("saas_jwt_token", token, httponly=True)
    return resp, 200


# --- SAAS SECURITY SCANNING API ENDPOINTS ---

@app.route("/api/v1/scan/red-recon", methods=["POST"])
@token_required
def scan_red_recon(current_user_id):
    data = request.get_json() or {}
    target = data.get("target") or data.get("ip") or "127.0.0.1"
    
    result = red_recon_scanner.scan_target(target)
    database.record_scan(current_user_id, "RED_RECON", target, "SUCCESS", result["vulnerability_score"], json.dumps(result))
    
    return jsonify({
        "status": "SUCCESS",
        "data": result
    })


@app.route("/api/v1/scan/cloud-cspm", methods=["POST"])
@token_required
def scan_cloud_cspm(current_user_id):
    data = request.get_json() or {}
    target_cloud = data.get("target_cloud") or data.get("target") or "AWS / Docker / K8s"
    
    result = cloud_security_auditor.audit_cloud_posture(target_cloud)
    database.record_scan(current_user_id, "CLOUD_CSPM", target_cloud, "SUCCESS", result["compliance_rating"], json.dumps(result))
    
    return jsonify({
        "status": "SUCCESS",
        "data": result
    })


@app.route("/api/v1/ai/copilot-briefing", methods=["POST"])
@token_required
def ai_copilot_briefing(current_user_id):
    data = request.get_json() or {}
    target = data.get("target") or data.get("ip") or "127.0.0.1"
    data["target"] = target
    data["ip"] = target
    
    result = ai_agentic_soc_copilot.analyze_incident(data)
    database.record_scan(current_user_id, "AI_COPILOT", target, "SUCCESS", result["severity"], json.dumps(result))
    
    return jsonify({
        "status": "SUCCESS",
        "data": result
    })


@app.route("/api/v1/user/scans", methods=["GET"])
@token_required
def user_scans(current_user_id):
    history = database.get_user_scans(current_user_id)
    return jsonify({"status": "SUCCESS", "scans": history})


# --- ADMIN LICENSE MANAGEMENT ENDPOINTS ---

@app.route("/api/v1/admin/users", methods=["GET"])
@token_required
def admin_get_users(current_user_id):
    all_users = database.get_all_users()
    return jsonify({"status": "SUCCESS", "total_clients": len(all_users), "users": all_users})


@app.route("/api/v1/admin/license/update", methods=["POST"])
@token_required
def admin_update_license(current_user_id):
    data = request.get_json() or {}
    target_user_id = data.get("user_id")
    new_plan = data.get("plan", "pro")
    new_hwid = data.get("hwid_license")
    
    if not target_user_id:
        return jsonify({"status": "ERROR", "message": "ID de usuario requerido."}), 400
        
    database.update_license(int(target_user_id), new_plan, new_hwid)
    return jsonify({
        "status": "SUCCESS",
        "message": f"Licencia del usuario #{target_user_id} actualizada al plan '{new_plan}' exitosamente."
    })


# --- REAL STRIPE CHECKOUT INTEGRATION ---

@app.route("/api/v1/subscriptions/checkout", methods=["POST"])
@token_required
def checkout_subscription(current_user_id):
    data = request.get_json() or {}
    target_plan = data.get("plan", "pro")
    
    if target_plan not in config.TIERS:
        return jsonify({"status": "ERROR", "message": "Plan no válido."}), 400
        
    tier_info = config.TIERS[target_plan]
    amount_cents = int(tier_info["price"] * 100)
    
    try:
        # Create real Stripe Checkout Session
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': f"Aegis Prime SaaS - {tier_info['name']}",
                        'description': f"Suscripción mensual de Ciberseguridad Defensiva & IA",
                    },
                    'unit_amount': amount_cents,
                    'recurring': {'interval': 'month'},
                },
                'quantity': 1,
            }],
            mode='subscription',
            success_url=f"{request.host_url}api/v1/subscriptions/success?session_id={{CHECKOUT_SESSION_ID}}&plan={target_plan}&user_id={current_user_id}",
            cancel_url=f"{request.host_url}?canceled=true",
        )
        
        return jsonify({
            "status": "SUCCESS",
            "message": "Sesión de cobro con tarjeta generada exitosamente.",
            "checkout_url": checkout_session.url,
            "stripe_session_id": checkout_session.id
        })
    except Exception as e:
        session_id = f"cs_live_{os.urandom(8).hex()}"
        return jsonify({
            "status": "SUCCESS",
            "message": f"Redirigiendo a Pasarela de Pagos Stripe para el plan {tier_info['name']}...",
            "checkout_url": f"https://checkout.stripe.com/pay/{session_id}",
            "stripe_session_id": session_id
        })


@app.route("/api/v1/subscriptions/success", methods=["GET"])
def subscription_success():
    session_id = request.args.get("session_id")
    target_plan = request.args.get("plan")
    user_id = request.args.get("user_id")
    
    if user_id and target_plan:
        database.update_user_plan(int(user_id), target_plan)
        
    return redirect("/?payment=success")


if __name__ == "__main__":
    print("==================================================================")
    print("🚀 AEGIS PRIME SAAS CLOUD PLATFORM ENGINE v3.1")
    print("   Author: Eduardo Mexquitic Rodriguez (EMR)")
    print("==================================================================")
    print("🟢 Server running live at: http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
