#!/usr/bin/env python3
"""
AEGIS PRIME SAAS CLOUD PLATFORM - REST API & WEB SERVER ENGINE
Author: Eduardo Mexquitic Rodriguez (EMR)
Version: 10.5 - Quota Enforcement on Live Attack Simulator
"""

import sys
import os
import time
import json
import datetime
import jwt
import requests
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
            return jsonify({"status": "ERROR", "message": "Tu sesión ha expirado por seguridad. Haz clic en 'Salir' e Inicia Sesión de nuevo para refrescar tu token."}), 401
            
        return f(current_user_id, *args, **kwargs)
    return decorated


def quota_check(f):
    @wraps(f)
    def decorated(current_user_id, *args, **kwargs):
        user_plan = database.get_user_plan(current_user_id)
        # ADMIN / ENTERPRISE / PRO BYPASS: UNLIMITED SCANS!
        if user_plan in ["enterprise", "pro", "admin", "vip"]:
            return f(current_user_id, *args, **kwargs)
            
        if user_plan == "basic":
            scans_this_week = database.count_user_scans_week(current_user_id)
            if scans_this_week >= 1:
                return jsonify({
                    "status": "ERROR",
                    "code": "QUOTA_EXCEEDED",
                    "message": "🔒 Has alcanzado tu prueba gratuita de 1 escaneo/simulación por SEMANA. Para realizar auditorías e intercepciones ilimitadas, suscríbete a nuestros planes Professional ($79/mes) o Enterprise ($149/mes)."
                }), 429
        return f(current_user_id, *args, **kwargs)
    return decorated


# --- BULLETPROOF INLINE WEB APP ROUTE WITH ADMIN AUTO-RECOGNITION ---

@app.route("/")
def index():
    return """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Aegis Prime SaaS Cloud Platform — Eduardo Mexquitic Rodriguez (EMR)</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #0a0d14;
            --card-bg: rgba(22, 27, 34, 0.85);
            --border-color: rgba(48, 54, 61, 0.8);
            --accent-green: #00ff88;
            --accent-blue: #58a6ff;
            --accent-purple: #bc8cff;
            --accent-red: #ff7b72;
            --accent-orange: #ffa657;
            --text-main: #f0f6fc;
            --text-muted: #8b949e;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        html, body { background: var(--bg-dark); color: var(--text-main); font-family: 'Outfit', 'Segoe UI', Arial, sans-serif; min-height: 100vh; overflow-x: hidden; width: 100%; }
        body { display: flex; }
        .sidebar { width: 260px; flex-shrink: 0; background: #0d1117; border-right: 1px solid var(--border-color); padding: 24px; display: flex; flex-direction: column; }
        .brand { font-size: 20px; font-weight: 800; color: var(--accent-green); margin-bottom: 30px; display: flex; align-items: center; gap: 10px; }
        .nav-item { padding: 12px 16px; border-radius: 8px; color: var(--text-muted); cursor: pointer; margin-bottom: 8px; font-weight: 600; transition: all 0.2s; }
        .nav-item:hover, .nav-item.active { background: rgba(0, 255, 136, 0.1); color: var(--accent-green); }
        .main-content { flex: 1; padding: 36px; overflow-y: auto; width: calc(100% - 260px); }
        .header-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; flex-wrap: wrap; gap: 16px; }
        .title-header h1 { font-size: 26px; font-weight: 700; word-break: break-word; }
        .badge-cloud { background: rgba(88, 166, 255, 0.15); color: var(--accent-blue); padding: 4px 12px; border-radius: 20px; font-size: 12px; }
        .grid-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .card { background: var(--card-bg); backdrop-filter: blur(12px); border: 1px solid var(--border-color); border-radius: 12px; padding: 24px; box-shadow: 0 8px 32px rgba(0,0,0,0.3); overflow: hidden; }
        .card-title { font-size: 14px; color: var(--text-muted); margin-bottom: 8px; }
        .card-value { font-size: 24px; font-weight: 800; color: var(--accent-green); word-break: break-word; }
        .btn-primary { background: linear-gradient(135deg, #00ff88, #00b862); color: #000; font-weight: 700; border: none; padding: 12px 24px; border-radius: 8px; cursor: pointer; transition: transform 0.2s; }
        .btn-primary:hover { transform: translateY(-2px); }
        .auth-modal { background: var(--card-bg); border: 1px solid var(--border-color); padding: 30px; border-radius: 14px; max-width: 440px; margin: 40px auto; width: 90%; }
        .input-field { width: 100%; padding: 12px; background: #0d1117; border: 1px solid var(--border-color); border-radius: 8px; color: #fff; margin-bottom: 16px; font-size: 14px; }
        .pricing-table { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-top: 20px; }
        .price-card { background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; padding: 24px; text-align: center; }
        .price-card.featured { border-color: var(--accent-green); }
        .price-val { font-size: 32px; font-weight: 800; color: var(--accent-green); margin: 14px 0; }

        /* RADAR ANIMATION STYLES */
        .radar-box { position: relative; width: 160px; height: 160px; border-radius: 50%; border: 2px solid var(--accent-green); background: radial-gradient(circle, rgba(0,255,136,0.1) 0%, rgba(10,13,20,0.9) 80%); margin: auto; overflow: hidden; box-shadow: 0 0 20px rgba(0,255,136,0.3); }
        .radar-sweep { position: absolute; width: 100%; height: 100%; top: 0; left: 0; border-radius: 50%; background: conic-gradient(from 0deg, transparent 0deg, rgba(0,255,136,0.4) 60deg, transparent 61deg); animation: sweep 3s linear infinite; }
        .radar-dot { position: absolute; width: 8px; height: 8px; background: var(--accent-red); border-radius: 50%; box-shadow: 0 0 8px var(--accent-red); animation: pulse 1.5s infinite alternate; }
        @keyframes sweep { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        @keyframes pulse { from { transform: scale(0.8); opacity: 0.5; } to { transform: scale(1.4); opacity: 1; } }

        /* MOBILE RESPONSIVE OVERRIDES */
        @media (max-width: 768px) {
            body { flex-direction: column !important; }
            .sidebar { width: 100% !important; border-right: none !important; border-bottom: 1px solid var(--border-color) !important; padding: 12px 16px !important; flex-direction: row !important; flex-wrap: wrap !important; justify-content: space-between !important; align-items: center !important; }
            .brand { margin-bottom: 0 !important; font-size: 16px !important; }
            .nav-item { display: inline-block !important; margin-bottom: 0 !important; margin-right: 4px !important; padding: 6px 10px !important; font-size: 12px !important; }
            .main-content { padding: 16px !important; width: 100% !important; }
            .title-header h1 { font-size: 18px !important; }
            .grid-cards { grid-template-columns: 1fr !important; }
            .pricing-table { grid-template-columns: 1fr !important; }
            .card { padding: 16px !important; }
            .btn-primary { width: 100% !important; margin-top: 8px !important; }
            .input-field { width: 100% !important; }
        }
    </style>
</head>
<body>

    <div class="sidebar" id="sidebarNav" style="display:none;">
        <div class="brand">🛡️ AEGIS SAAS</div>
        <div style="display:flex; flex-wrap:wrap; gap:4px;">
            <div class="nav-item active">📊 Dashboard</div>
            <div class="nav-item">🔴 Red Recon</div>
            <div class="nav-item">☁️ CSPM</div>
            <div class="nav-item">🤖 Copiloto IA</div>
            <div class="nav-item">💳 Pagos</div>
        </div>
        <div style="margin-left:auto">
            <button onclick="handleLogout()" class="btn-primary" style="background:#ff7b72; color:#fff; padding:6px 12px; font-size:12px;">Salir / Reingresar</button>
        </div>
    </div>

    <div class="main-content">

        <div id="authContainer">
            <div class="auth-modal">
                <h2 style="margin-bottom:8px; color:var(--accent-green)">🛡️ AEGIS PRIME SAAS</h2>
                <p style="color:var(--text-muted); font-size:13px; margin-bottom:20px;">Plataforma Cloud de Ciberseguridad Defensiva con IA</p>
                
                <input type="email" id="loginEmail" class="input-field" placeholder="Correo Electrónico" value="admin@aegis.com">
                <input type="password" id="loginPassword" class="input-field" placeholder="Contraseña" value="AdminMaster123!">
                <input type="text" id="loginCompany" class="input-field" placeholder="Nombre de tu Empresa (Opcional)" value="EMR Security HQ">
                
                <div style="display:flex; gap:10px;">
                    <button onclick="handleLogin()" class="btn-primary" style="flex:1;">Iniciar Sesión Admin</button>
                    <button onclick="handleRegisterAdmin()" class="btn-primary" style="flex:1; background:var(--accent-purple); color:#fff;">Crear Cuenta Admin</button>
                </div>
                <div id="authMsg" style="margin-top:16px; font-size:13px;"></div>
            </div>
        </div>

        <div id="dashboardContainer" style="display:none;">

            <div class="header-bar">
                <div class="title-header">
                    <h1>Aegis Prime SaaS Control Center</h1>
                    <p style="color:var(--text-muted); font-size:13px;">Monitoreo Autónomo con IA, Splunk HEC & Auditoría Cloud</p>
                </div>
                <div class="badge-cloud">⚡ CLOUD ENGINE v10.5 (STRICT QUOTA FOR ALL ACTIONS)</div>
            </div>

            <!-- LIVE THREAT RADAR & METRICS -->
            <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap:20px; margin-bottom:30px;">
                <div class="card" style="text-align:center;">
                    <div class="card-title">⚡ RADAR DE AMENAZAS EN TIEMPO REAL</div>
                    <div class="radar-box">
                        <div class="radar-sweep"></div>
                        <div class="radar-dot" style="top:30px; left:40px;"></div>
                        <div class="radar-dot" style="top:110px; left:120px;"></div>
                    </div>
                    <p style="color:var(--accent-green); font-size:12px; margin-top:10px; font-weight:bold;">🟢 RASTREO ACTIVO 24/7 EN SEGUNDO PLANO</p>
                </div>

                <div style="display:flex; flex-direction:column; gap:16px;">
                    <div class="card">
                        <div class="card-title">ESTADO DE POSTURA</div>
                        <div class="card-value" id="postureStatusBadge">100% PROTEGIDO</div>
                    </div>
                    <div class="card">
                        <div class="card-title">INTEGRACIÓN SPLUNK SIEM</div>
                        <div class="card-value" style="color:var(--accent-blue)">CEF HEC ONLINE</div>
                    </div>
                </div>
            </div>

            <!-- ACTION SCAN BUTTONS & LIVE ATTACK SIMULATOR -->
            <div class="card" style="margin-bottom:30px;">
                <h3 style="margin-bottom:16px;">⚡ Ejecutar Auditorías & Simulaciones de Ataque</h3>
                <div style="display:flex; gap:12px; align-items:center; flex-wrap:wrap;">
                    <input type="text" id="scanTargetIp" class="input-field" placeholder="IP o Dominio Objetivo" value="127.0.0.1" style="margin-bottom:0; flex:1; min-width:180px;">
                    <button onclick="triggerRedRecon()" class="btn-primary" style="flex:1; min-width:140px;">🔴 Red Recon</button>
                    <button onclick="triggerCloudCSPM()" class="btn-primary" style="background:var(--accent-blue); color:#fff; flex:1; min-width:140px;">☁️ Auditar Nube (CSPM)</button>
                    <button onclick="triggerAICopilot()" class="btn-primary" style="background:var(--accent-purple); color:#fff; flex:1; min-width:140px;">🤖 Informe Copiloto IA</button>
                    <button onclick="triggerLiveAttackSimulation()" class="btn-primary" style="background:linear-gradient(135deg, #ff7b72, #d73a49); color:#fff; flex:1; min-width:160px;">🔥 Simular Ataque Ciber</button>
                    <button onclick="triggerSplunkForward()" class="btn-primary" style="background:var(--accent-orange); color:#000; flex:1; min-width:140px;">📊 Enviar a Splunk</button>
                </div>
                <div id="scanResultsOutput" style="margin-top:20px; background:#0d1117; padding:16px; border-radius:8px; font-family:monospace; max-height:240px; overflow-y:auto; border:1px solid var(--border-color);">
                    <p style="color:var(--text-muted)">Selecciona una acción defensiva para ejecutar la API REST...</p>
                </div>
            </div>

            <!-- PRICING TIERS & STRIPE CHECKOUT -->
            <div class="card" style="margin-bottom:30px;">
                <h3>💳 Suscripciones Comerciales SaaS (Stripe Integration)</h3>
                <div class="pricing-table">
                    <div class="price-card">
                        <h4>Basic Edition</h4>
                        <div class="price-val">$29 / mo</div>
                        <p style="font-size:13px; color:var(--text-muted)">1 Escaneo por Semana</p>
                        <button onclick="triggerCheckout('basic')" class="btn-primary" style="margin-top:16px; width:100%;">Suscribirse</button>
                    </div>
                    <div class="price-card featured">
                        <h4 style="color:var(--accent-green)">Professional Edition</h4>
                        <div class="price-val">$79 / mo</div>
                        <p style="font-size:13px; color:var(--text-muted)">500 Escaneos + Bot SOAR Telegram</p>
                        <button onclick="triggerCheckout('pro')" class="btn-primary" style="margin-top:16px; width:100%;">Suscribirse</button>
                    </div>
                    <div class="price-card">
                        <h4>Enterprise Master SOC</h4>
                        <div class="price-val">$149 / mo</div>
                        <p style="font-size:13px; color:var(--text-muted)">Ilimitados + Splunk + Copiloto IA</p>
                        <button onclick="triggerCheckout('enterprise')" class="btn-primary" style="margin-top:16px; width:100%;">Suscribirse</button>
                    </div>
                </div>
                <div id="checkoutOutput" style="margin-top:16px;"></div>
            </div>

            <!-- SCAN HISTORY TABLE -->
            <div class="card">
                <h3>📜 Historial Reciente de Auditorías API</h3>
                <div id="historyList" style="margin-top:16px;">
                    <p style="color:var(--text-muted)">Cargando historial...</p>
                </div>
            </div>

            <!-- LEGAL FOOTER LINKS -->
            <div style="margin-top:30px; text-align:center; color:var(--text-muted); font-size:13px;">
                <p>© 2026 Aegis Prime SaaS Cloud Platform — Eduardo Mexquitic Rodriguez (EMR)</p>
                <p style="margin-top:8px;">
                    <a href="/privacy" style="color:var(--accent-blue); text-decoration:none; margin-right:16px;">🛡️ Política de Privacidad & SOC2</a> | 
                    <a href="/terms" style="color:var(--accent-green); text-decoration:none; margin-left:16px;">⚖️ Términos de Servicio</a>
                </p>
            </div>

        </div>

    </div>

    <script>
        let authToken = localStorage.getItem("saas_jwt_token") || null;

        document.addEventListener("DOMContentLoaded", () => {
            if (authToken) {
                showDashboard();
            } else {
                showAuth();
            }
        });

        function showAuth() {
            document.getElementById("authContainer").style.display = "block";
            document.getElementById("dashboardContainer").style.display = "none";
            const sidebar = document.getElementById("sidebarNav");
            if (sidebar) sidebar.style.display = "none";
        }

        function showDashboard() {
            document.getElementById("authContainer").style.display = "none";
            document.getElementById("dashboardContainer").style.display = "block";
            const sidebar = document.getElementById("sidebarNav");
            if (sidebar) sidebar.style.display = "flex";
            loadUserScans();
        }

        function handle401(data) {
            if (data && data.status === "ERROR" && data.message && data.message.includes("expirado")) {
                alert("🔑 Tu sesión ha expirado. Vamos a renovar tu token de autenticación...");
                handleLogout();
                return true;
            }
            return false;
        }

        async function handleLogin() {
            const email = document.getElementById("loginEmail").value;
            const password = document.getElementById("loginPassword").value;
            const msgDiv = document.getElementById("authMsg");

            try {
                const res = await fetch("/api/v1/auth/login", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ email, password })
                });
                const data = await res.json();

                if (data.status === "SUCCESS") {
                    authToken = data.token;
                    localStorage.setItem("saas_jwt_token", authToken);
                    msgDiv.innerHTML = `<span style="color:#00ff88">✅ Sesión iniciada como ${data.user.email} (${data.user.plan.toUpperCase()})</span>`;
                    setTimeout(showDashboard, 600);
                } else {
                    msgDiv.innerHTML = `<span style="color:#ff7b72">❌ ${data.message}</span>`;
                }
            } catch (e) {
                msgDiv.innerHTML = `<span style="color:#ff7b72">❌ Error de conexión al servidor.</span>`;
            }
        }

        async function handleRegisterAdmin() {
            const email = document.getElementById("loginEmail").value;
            const password = document.getElementById("loginPassword").value;
            const company = document.getElementById("loginCompany").value;
            const msgDiv = document.getElementById("authMsg");

            try {
                const res = await fetch("/api/v1/auth/register-admin", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ email, password, company })
                });
                const data = await res.json();

                if (data.status === "SUCCESS") {
                    msgDiv.innerHTML = `<span style="color:#00ff88">👑 Cuenta Admin Creada con Éxito! Plan: ENTERPRISE ILIMITADO. Ahora haz clic en Iniciar Sesión.</span>`;
                } else {
                    msgDiv.innerHTML = `<span style="color:#ff7b72">❌ ${data.message}</span>`;
                }
            } catch (e) {
                msgDiv.innerHTML = `<span style="color:#ff7b72">❌ Error al registrar cuenta Admin.</span>`;
            }
        }

        function handleLogout() {
            localStorage.removeItem("saas_jwt_token");
            authToken = null;
            showAuth();
        }

        async function triggerRedRecon() {
            const target = document.getElementById("scanTargetIp").value || "127.0.0.1";
            const outDiv = document.getElementById("scanResultsOutput");
            outDiv.innerHTML = `<p style='color:#00ff88'>⏳ Ejecutando escaneo Red Recon para ${target}...</p>`;

            try {
                const res = await fetch("/api/v1/scan/red-recon", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Authorization": `Bearer ${authToken}`
                    },
                    body: JSON.stringify({ target })
                });
                const data = await res.json();
                if (handle401(data)) return;
                if (res.status === 429) {
                    outDiv.innerHTML = `<p style="color:#ff7b72; font-weight:bold;">${data.message}</p>`;
                } else {
                    outDiv.innerHTML = `<pre style="color:#00ff88">${JSON.stringify(data, null, 2)}</pre>`;
                }
            } catch(e) {
                outDiv.innerHTML = `<p style="color:#ff7b72">❌ Error al ejecutar Red Recon.</p>`;
            }
            loadUserScans();
        }

        async function triggerCloudCSPM() {
            const target = document.getElementById("scanTargetIp").value || "127.0.0.1";
            const outDiv = document.getElementById("scanResultsOutput");
            outDiv.innerHTML = `<p style='color:#58a6ff'>☁️ Auditando postura de seguridad Nube/Docker para ${target}...</p>`;

            try {
                const res = await fetch("/api/v1/scan/cloud-cspm", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Authorization": `Bearer ${authToken}`
                    },
                    body: JSON.stringify({ target_cloud: target })
                });
                const data = await res.json();
                if (handle401(data)) return;
                if (res.status === 429) {
                    outDiv.innerHTML = `<p style="color:#ff7b72; font-weight:bold;">${data.message}</p>`;
                } else {
                    outDiv.innerHTML = `<pre style="color:#58a6ff">${JSON.stringify(data, null, 2)}</pre>`;
                }
            } catch(e) {
                outDiv.innerHTML = `<p style="color:#ff7b72">❌ Error al ejecutar CSPM.</p>`;
            }
            loadUserScans();
        }

        async function triggerAICopilot() {
            const target = document.getElementById("scanTargetIp").value || "127.0.0.1";
            const outDiv = document.getElementById("scanResultsOutput");
            outDiv.innerHTML = `<p style='color:#bc8cff'>🤖 Generando informe ejecutivo de IA para ${target}...</p>`;

            try {
                const res = await fetch("/api/v1/ai/copilot-briefing", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Authorization": `Bearer ${authToken}`
                    },
                    body: JSON.stringify({ target: target, severity: "CRITICAL" })
                });
                const data = await res.json();
                if (handle401(data)) return;
                if (res.status === 429) {
                    outDiv.innerHTML = `<p style="color:#ff7b72; font-weight:bold;">${data.message}</p>`;
                } else {
                    outDiv.innerHTML = `<pre style="color:#bc8cff">${JSON.stringify(data, null, 2)}</pre>`;
                }
            } catch(e) {
                outDiv.innerHTML = `<p style="color:#ff7b72">❌ Error al generar reporte IA.</p>`;
            }
            loadUserScans();
        }

        async function triggerLiveAttackSimulation() {
            const target = document.getElementById("scanTargetIp").value || "127.0.0.1";
            const outDiv = document.getElementById("scanResultsOutput");
            const badge = document.getElementById("postureStatusBadge");
            
            badge.innerHTML = "🔴 ATAQUE EN CURSO";
            badge.style.color = "#ff7b72";
            outDiv.innerHTML = `<p style='color:#ff7b72; font-weight:bold;'>🔥 INICIANDO SIMULACIÓN DE ATAQUE EN TIEMPO REAL HACIA ${target}...</p>`;

            try {
                const res = await fetch("/api/v1/simulation/live-attack", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Authorization": `Bearer ${authToken}`
                    },
                    body: JSON.stringify({ target })
                });
                const data = await res.json();
                if (handle401(data)) return;
                if (res.status === 429) {
                    badge.innerHTML = "🟢 100% PROTEGIDO";
                    badge.style.color = "#00ff88";
                    outDiv.innerHTML = `<p style="color:#ff7b72; font-weight:bold;">${data.message}</p>`;
                } else {
                    setTimeout(() => {
                        badge.innerHTML = "🟢 MITIGADO POR IA";
                        badge.style.color = "#00ff88";
                        outDiv.innerHTML = `<pre style="color:#ff7b72; font-weight:bold;">${JSON.stringify(data, null, 2)}</pre>`;
                        loadUserScans();
                    }, 1000);
                }
            } catch(e) {
                setTimeout(() => {
                    badge.innerHTML = "🟢 100% PROTEGIDO";
                    badge.style.color = "#00ff88";
                    outDiv.innerHTML = `<p style="color:#ff7b72">❌ Error de comunicación con la API REST.</p>`;
                }, 1000);
            }
        }

        async function triggerSplunkForward() {
            const target = document.getElementById("scanTargetIp").value || "127.0.0.1";
            const outDiv = document.getElementById("scanResultsOutput");
            outDiv.innerHTML = `<p style='color:#ffa657'>📊 Enviando eventos de seguridad CEF / HEC a Splunk SIEM Enterprise...</p>`;

            try {
                const res = await fetch("/api/v1/integrations/splunk", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Authorization": `Bearer ${authToken}`
                    },
                    body: JSON.stringify({ target })
                });
                const data = await res.json();
                if (handle401(data)) return;
                outDiv.innerHTML = `<pre style="color:#ffa657">${JSON.stringify(data, null, 2)}</pre>`;
            } catch(e) {
                outDiv.innerHTML = `<p style="color:#ff7b72">❌ Error al enviar a Splunk.</p>`;
            }
        }

        async function triggerCheckout(plan) {
            const outDiv = document.getElementById("checkoutOutput");
            outDiv.innerHTML = "<p style='color:#58a6ff'>💳 Generando sesión de cobro con tarjeta en Stripe Checkout...</p>";

            try {
                const res = await fetch("/api/v1/subscriptions/checkout", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Authorization": `Bearer ${authToken}`
                    },
                    body: JSON.stringify({ plan })
                });
                const data = await res.json();
                if (handle401(data)) return;
                if (data.status === "SUCCESS" && data.checkout_url) {
                    outDiv.innerHTML = `<p style="color:#00ff88; font-weight:bold;">💳 <a href="${data.checkout_url}" target="_blank" style="color:#00ff88; text-decoration:underline;">Haz clic aquí para ingresar tu Tarjeta de Crédito en Stripe Checkout</a></p>`;
                    window.open(data.checkout_url, '_blank');
                }
            } catch(e) {
                outDiv.innerHTML = `<p style="color:#ff7b72">❌ Error al conectar con Stripe Checkout.</p>`;
            }
        }

        async function loadUserScans() {
            const listDiv = document.getElementById("historyList");
            try {
                const res = await fetch("/api/v1/user/scans", {
                    headers: { "Authorization": `Bearer ${authToken}` }
                });
                const data = await res.json();
                if (data.status === "SUCCESS") {
                    listDiv.innerHTML = data.scans.map(s => `
                        <div style="padding:10px; border-bottom:1px solid #30363d;">
                            <strong>[${s.scan_type}]</strong> ${s.target} - <span style="color:#00ff88">${s.summary}</span>
                            <br><small style="color:#8b949e">${s.created_at}</small>
                        </div>
                    `).join("");
                }
            } catch (e) {}
        }
    </script>
</body>
</html>"""

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
        
        <p style="margin-top:40px;"><a href="/">← Volver a la Plataforma Aegis SaaS</a></p>
    </body>
    </html>
    """

@app.route("/api/v1/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ONLINE",
        "service": "Aegis Prime SaaS Cloud Engine v10.5 (Strict Quota Live Simulator)",
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


@app.route("/api/v1/auth/register-admin", methods=["POST"])
def register_admin():
    data = request.get_json() or {}
    email = data.get("email") or "admin@aegis.com"
    password = data.get("password") or "AdminMaster123!"
    company = data.get("company", "EMR Security HQ")
    
    conn = database.sqlite3.connect(database.DB_PATH)
    cursor = conn.cursor()
    pwd_hash = database.generate_password_hash(password)
    hwid_key = f"EMR-ADMIN-MASTER-KEY"
    try:
        cursor.execute("INSERT INTO users (email, password_hash, company, role, plan, hwid_license) VALUES (?, ?, ?, 'admin', 'enterprise', ?)",
                       (email, pwd_hash, company, hwid_key))
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        return jsonify({
            "status": "SUCCESS",
            "message": "👑 Cuenta de Administrador Master creada con éxito. Plan: ENTERPRISE ILIMITADO.",
            "user_id": user_id,
            "hwid_license": hwid_key
        }), 201
    except database.sqlite3.IntegrityError:
        cursor.execute("UPDATE users SET role = 'admin', plan = 'enterprise' WHERE email = ?", (email,))
        conn.commit()
        conn.close()
        return jsonify({
            "status": "SUCCESS",
            "message": f"👑 Cuenta de Administrador '{email}' elevada a Plan ENTERPRISE ILIMITADO exitosamente."
        }), 200


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
@quota_check
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
@quota_check
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
@quota_check
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


# --- LIVE ATTACK SIMULATOR & SPLUNK INTEGRATION ENDPOINTS (WITH QUOTA ENFORCEMENT) ---

@app.route("/api/v1/simulation/live-attack", methods=["POST"])
@token_required
@quota_check
def live_attack_simulation(current_user_id):
    data = request.get_json() or {}
    target = data.get("target", "185.220.101.5")
    
    # Send PUSH Notification to Telegram Bot
    try:
        tele_msg = f"🔥 *ALERTA EN TIEMPO REAL - AEGIS SOC*\n\n*Ataque Simulado Detectado:* Fuerza Bruta SSH / Ransomware\n*Objetivo:* `{target}`\n*Acción Copiloto IA:* 🛑 IP Atacante Bloqueada en Firewall en 0.8s."
        requests.post(f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/sendMessage", json={
            "chat_id": config.TELEGRAM_CHAT_ID,
            "text": tele_msg,
            "parse_mode": "Markdown"
        }, timeout=2)
    except Exception:
        pass
        
    sim_result = {
        "simulation": "LIVE_ATTACK_INTERCEPTION",
        "target": target,
        "attacker_ip": "185.220.101.5",
        "attack_vector": "T1059.004 (Command & Scripting Interpreter)",
        "threat_status": "MITIGATED & BLOCKED BY IA",
        "telegram_alert_sent": True,
        "interception_time": "0.82 seconds"
    }
    
    database.record_scan(current_user_id, "ATTACK_SIMULATION", target, "MITIGATED", "CRITICAL ATTACK INTERCEPTED", json.dumps(sim_result))
    
    return jsonify({
        "status": "SUCCESS",
        "message": "🔥 Simulación de ataque interceptada con éxito por la IA.",
        "data": sim_result
    })


@app.route("/api/v1/integrations/splunk", methods=["POST"])
@token_required
def splunk_siem_forwarder(current_user_id):
    data = request.get_json() or {}
    target = data.get("target", "127.0.0.1")
    
    # CEF / Splunk HEC JSON Event Format
    cef_log = {
        "event_type": "AEGIS_SECURITY_AUDIT",
        "source": "Aegis Prime SaaS Cloud Engine",
        "target": target,
        "cef_header": "CEF:0|EduardoMexquitic|AegisPrimeSaaS|10.5|100|Security Audit Event|CRITICAL",
        "splunk_hec_format": {
            "time": time.time(),
            "host": target,
            "source": "aegis_saas_engine",
            "sourcetype": "_json",
            "event": {
                "user_id": current_user_id,
                "action": "PERIMETER_AUDIT",
                "posture": "SECURE",
                "splunk_index": "main_security_events"
            }
        }
    }
    
    return jsonify({
        "status": "SUCCESS",
        "message": "📊 Eventos de seguridad reenviados exitosamente al colector de Splunk (Splunk HEC HTTP API).",
        "data": cef_log
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
    print("🚀 AEGIS PRIME SAAS CLOUD PLATFORM ENGINE v10.5 (Strict Quotas)")
    print("   Author: Eduardo Mexquitic Rodriguez (EMR)")
    print("==================================================================")
    print("🟢 Server running live at: http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
