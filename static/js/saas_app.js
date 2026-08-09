/**
 * AEGIS PRIME SAAS CLOUD PLATFORM - FRONTEND ENGINE
 * Author: Eduardo Mexquitic Rodriguez (EMR)
 */

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
            msgDiv.innerHTML = `<span style="color:#00ff88">✅ Login Exitoso! Bienvenido ${data.user.email}</span>`;
            setTimeout(showDashboard, 800);
        } else {
            msgDiv.innerHTML = `<span style="color:#ff7b72">❌ ${data.message}</span>`;
        }
    } catch (e) {
        msgDiv.innerHTML = `<span style="color:#ff7b72">❌ Error de conexión al servidor.</span>`;
    }
}

async function handleRegister() {
    const email = document.getElementById("loginEmail").value;
    const password = document.getElementById("loginPassword").value;
    const company = document.getElementById("loginCompany").value;
    const msgDiv = document.getElementById("authMsg");

    try {
        const res = await fetch("/api/v1/auth/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, password, company })
        });
        const data = await res.json();

        if (data.status === "SUCCESS") {
            msgDiv.innerHTML = `<span style="color:#00ff88">✅ Cuenta creada! Clave Licencia: ${data.hwid_license}</span>`;
        } else {
            msgDiv.innerHTML = `<span style="color:#ff7b72">❌ ${data.message}</span>`;
        }
    } catch (e) {
        msgDiv.innerHTML = `<span style="color:#ff7b72">❌ Error al registrar cuenta.</span>`;
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
    outDiv.innerHTML = "<p style='color:#00ff88'>⏳ Ejecutando escaneo Red Recon en vivo...</p>";

    const res = await fetch("/api/v1/scan/red-recon", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${authToken}`
        },
        body: JSON.stringify({ target })
    });
    const data = await res.json();
    outDiv.innerHTML = `<pre style="color:#00ff88">${JSON.stringify(data, null, 2)}</pre>`;
    loadUserScans();
}

async function triggerCloudCSPM() {
    const outDiv = document.getElementById("scanResultsOutput");
    outDiv.innerHTML = "<p style='color:#58a6ff'>☁️ Auditando postura de seguridad en Nube y Contenedores...</p>";

    const res = await fetch("/api/v1/scan/cloud-cspm", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${authToken}`
        },
        body: JSON.stringify({ target_cloud: "AWS / Docker / K8s" })
    });
    const data = await res.json();
    outDiv.innerHTML = `<pre style="color:#58a6ff">${JSON.stringify(data, null, 2)}</pre>`;
    loadUserScans();
}

async function triggerAICopilot() {
    const outDiv = document.getElementById("scanResultsOutput");
    outDiv.innerHTML = "<p style='color:#bc8cff'>🤖 Generando informe ejecutivo con el Copiloto de IA Autónoma...</p>";

    const res = await fetch("/api/v1/ai/copilot-briefing", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${authToken}`
        },
        body: JSON.stringify({ ip: "185.220.101.5", severity: "CRITICAL" })
    });
    const data = await res.json();
    outDiv.innerHTML = `<pre style="color:#bc8cff">${JSON.stringify(data, null, 2)}</pre>`;
    loadUserScans();
}

async function triggerCheckout(plan) {
    const outDiv = document.getElementById("checkoutOutput");
    outDiv.innerHTML = "<p style='color:#58a6ff'>💳 Conectando con Stripe Checkout API...</p>";

    const res = await fetch("/api/v1/subscriptions/checkout", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${authToken}`
        },
        body: JSON.stringify({ plan })
    });
    const data = await res.json();
    if (data.status === "SUCCESS") {
        outDiv.innerHTML = `<p style="color:#00ff88; font-weight:bold;">🎉 ${data.message} Session ID: ${data.stripe_session_id}</p>`;
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
