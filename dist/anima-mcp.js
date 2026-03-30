#!/usr/bin/env node

/**
 * @file anima-mcp-bridge.js
 * @description Bridge between Microsoft Entra ID and Anima MCP Server.
 * @version 1.2.2 (Ânima MCP bridge - Production)
 * @license GPL-3.0
 */

const { spawn, spawnSync } = require("child_process");
const https = require("https");
const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const readline = require("readline");

const CONFIG = {
    TENANT_ID: process.env.ANIMA_TENANT_ID || "f310b526-e195-4805-a55e-67e28f2fefdb",
    CLIENT_ID: process.env.ANIMA_CLIENT_ID || "83cc2f94-3027-455f-be73-67344586b7df",
    API_SCOPE: "api://servico_hackathon_mcp/Api.Read",
    PAT_URL: process.env.ANIMA_PAT_URL || "https://cloudapp.animaeducacao.com.br/servico-hackathon-mcp/auth/pats",
    REMOTE_MCP_URL: process.env.ANIMA_MCP_URL || "https://cloudapp.animaeducacao.com.br/servico-hackathon-mcp/mcp",
    CACHE_PATH: path.join(os.homedir(), ".anima-mcp-cache.enc"),
    WINDOW_TITLE: "AnimaMCPAuth",
    USER_AGENT: "Anima-MCP-Bridge/1.1.8",
    PINNED_MCP_REMOTE_VER: "mcp-remote@0.1.3",
    REQUEST_TIMEOUT: 15000,
    MAX_AUTH_POLLING_SEC: 900,
    DEFAULT_PAT_TTL: 900,
    RESTART_BUFFER_MS: 120000,
    RETRY: {
        MAX_RETRIES: 5,
        INITIAL_DELAY_MS: 1000,
        MAX_DELAY_MS: 30000,
        RETRYABLE_STATUS_CODES: [401, 403, 408, 429, 500, 502, 503, 504]
    }
};

const correlationId = crypto.randomBytes(4).toString('hex');

const log = (msg, level = "INFO") => {
    const timestamp = new Date().toISOString();
    process.stderr.write(`[${timestamp}] [${correlationId}] [${level}] ${msg}\n`);
};

function getEncryptionKey() {
    const machineFingerprint = os.userInfo().username + os.homedir();
    return crypto.scryptSync(machineFingerprint, 'anima-salt-v1', 32);
}
function encrypt(text) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', getEncryptionKey(), iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return `${iv.toString('hex')}:${cipher.getAuthTag().toString('hex')}:${encrypted}`;
}
function decrypt(cipherText) {
    try {
        const [ivHex, authTagHex, encrypted] = cipherText.split(':');
        const decipher = crypto.createDecipheriv('aes-256-gcm', getEncryptionKey(), Buffer.from(ivHex, 'hex'));
        decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
        return decipher.update(encrypted, 'hex', 'utf8') + decipher.final('utf8');
    } catch (e) { return null; }
}
function loadCache() {
    if (fs.existsSync(CONFIG.CACHE_PATH)) {
        try {
            const decrypted = decrypt(fs.readFileSync(CONFIG.CACHE_PATH, "utf8"));
            if (decrypted) return JSON.parse(decrypted);
        } catch (e) {}
    }
    return {};
}
function saveCache(data) {
    const updated = { ...loadCache(), ...data };
    fs.writeFileSync(CONFIG.CACHE_PATH, encrypt(JSON.stringify(updated)));
}

let activeGuiProcess = null;
function cleanupGui() {
    if (!activeGuiProcess) return;
    try {
        if (process.platform === "win32") spawnSync("taskkill", ["/FI", `WINDOWTITLE eq ${CONFIG.WINDOW_TITLE}*`, "/F", "/T"], { stdio: 'ignore' });
        else activeGuiProcess.kill('SIGTERM');
    } catch (e) { }
    activeGuiProcess = null;
}

function showAuthGui(userCode, verificationUri) {
    const platform = process.platform;
    if (platform === "win32") {
        const xaml = `<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Title="${CONFIG.WINDOW_TITLE}" Width="480" SizeToContent="Height" WindowStartupLocation="CenterScreen" Background="#F3F3F3" ResizeMode="NoResize" Topmost="True"><StackPanel Margin="30,30,30,40"><TextBlock Text="Connect to Anima MCP" FontSize="22" FontWeight="Bold" Margin="0,0,0,10"/><TextBlock Text="Please authenticate with your student credentials." TextWrapping="Wrap" Margin="0,0,0,25"/><Border Background="White" BorderBrush="#DDDDDD" BorderThickness="1" CornerRadius="5" Padding="20"><TextBlock Text="${userCode}" FontSize="32" FontWeight="ExtraBold" HorizontalAlignment="Center" Foreground="#0078D4"/></Border><Grid Margin="0,30,0,0"><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions><Button Name="CopyBtn" Content="Copy Code" Grid.Column="0" Margin="0,0,8,0" Height="40"/><Button Name="LaunchBtn" Content="Open Browser" Grid.Column="1" Margin="8,0,0,0" Height="40" Background="#0078D4" Foreground="White"/></Grid></StackPanel></Window>`;
        const xamlBase64 = Buffer.from(xaml).toString('base64');
        const psScript = `Add-Type -AssemblyName PresentationFramework; $window = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader ([xml][System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('${xamlBase64}'))))); $window.FindName('CopyBtn').Add_Click({ Set-Clipboard -Value '${userCode}' }); $window.FindName('LaunchBtn').Add_Click({ Set-Clipboard -Value '${userCode}'; Start-Process '${verificationUri}'; }); Set-Clipboard -Value '${userCode}'; $window.ShowDialog() | Out-Null;`.replace(/\n/g, ' ');
        activeGuiProcess = spawn("powershell.exe", ["-NoProfile", "-Command", psScript]);
    } else if (platform === "darwin") {
        const appleScript = `set theCode to "${userCode}"\nset the clipboard to theCode\ndisplay dialog "To connect to Anima MCP, use this code in your browser:\\n\\n" & theCode & "\\n\\nThe code has been copied to your clipboard." with title "Anima MCP Auth" buttons {"Open Browser", "Cancel"} default button "Open Browser"\nif button returned of result is "Open Browser" then\nopen location "${verificationUri}"\nend if`;
        activeGuiProcess = spawn("osascript", ["-e", appleScript]);
    }
}

function askConsent() {
    if (process.platform === "win32") {
        const psScript = `Add-Type -AssemblyName PresentationFramework; $res = [System.Windows.MessageBox]::Show('Connect to Anima MCP?', 'Anima MCP', 'YesNo', 'Information'); if ($res -eq 'Yes') { exit 0 } else { exit 1 }`;
        return spawnSync("powershell.exe", ["-NoProfile", "-Command", psScript]).status === 0;
    }
    return true; 
}

function request(url, method, headers, body) {
    return new Promise((resolve) => {
        const payload = typeof body === "string" ? body : JSON.stringify(body);
        const req = https.request(url, { method, headers: { ...headers, "Content-Length": Buffer.byteLength(payload), "User-Agent": CONFIG.USER_AGENT }, timeout: CONFIG.REQUEST_TIMEOUT }, (res) => {
            let data = "";
            res.on("data", (chunk) => (data += chunk));
            res.on("end", () => { try { resolve({ status: res.statusCode, data: JSON.parse(data || "{}") }); } catch (e) { resolve({ status: res.statusCode, data: { raw: data } }); } });
        });
        req.on("error", (e) => resolve({ status: 500, data: { error: e.message } }));
        req.write(payload);
        req.end();
    });
}

async function requestWithRetry(url, method, headers, body) {
    let attempt = 0;
    while (attempt < CONFIG.RETRY.MAX_RETRIES) {
        const response = await request(url, method, headers, body);
        
        if (response.status >= 200 && response.status < 300) return response;

        if (!CONFIG.RETRY.RETRYABLE_STATUS_CODES.includes(response.status)) return response;

        attempt++;
        if (attempt >= CONFIG.RETRY.MAX_RETRIES) return response;

        const backoff = Math.min(CONFIG.RETRY.MAX_DELAY_MS, CONFIG.RETRY.INITIAL_DELAY_MS * Math.pow(2, attempt));
        const jitter = Math.random() * 1000;
        const totalDelay = backoff + jitter;

        log(`Request failed (${response.status}). Retrying in ${Math.round(totalDelay)}ms... (Attempt ${attempt}/${CONFIG.RETRY.MAX_RETRIES})`, "WARN");
        await new Promise(resolve => setTimeout(resolve, totalDelay));
    }
}

async function getValidToken() {
    const cache = loadCache();
    if (cache.entra?.access_token && Date.now() < (cache.entra.expires_at - 120000)) return cache.entra.access_token;
    
    if (cache.entra?.refresh_token) {
        log("Refreshing Microsoft Entra token...", "INFO");
        const res = await requestWithRetry(
            `https://login.microsoftonline.com/${CONFIG.TENANT_ID}/oauth2/v2.0/token`, 
            "POST", 
            { "Content-Type": "application/x-www-form-urlencoded" }, 
            `grant_type=refresh_token&client_id=${CONFIG.CLIENT_ID}&refresh_token=${cache.entra.refresh_token}&scope=${encodeURIComponent(CONFIG.API_SCOPE + " offline_access openid profile")}`
        );
        
        if (res.data.access_token) {
            const data = { access_token: res.data.access_token, refresh_token: res.data.refresh_token || cache.entra.refresh_token, expires_at: Date.now() + (res.data.expires_in * 1000) };
            saveCache({ entra: data });
            return data.access_token;
        }
    }

    if (!askConsent()) throw new Error("User declined authentication.");
    
    const deviceRes = await requestWithRetry(
        `https://login.microsoftonline.com/${CONFIG.TENANT_ID}/oauth2/v2.0/devicecode`, 
        "POST", 
        { "Content-Type": "application/x-www-form-urlencoded" }, 
        `client_id=${CONFIG.CLIENT_ID}&scope=${encodeURIComponent(CONFIG.API_SCOPE + " offline_access openid profile")}`
    );

    if (!deviceRes.data.user_code) throw new Error("Failed to initiate device code flow.");

    showAuthGui(deviceRes.data.user_code, "https://login.microsoftonline.com/common/oauth2/deviceauth");
    
    const startTime = Date.now();
    while (true) {
        if ((Date.now() - startTime) / 1000 > CONFIG.MAX_AUTH_POLLING_SEC) { cleanupGui(); throw new Error("Authentication timed out."); }
        await new Promise(r => setTimeout(r, 5000));
        
        const tRes = await request(`https://login.microsoftonline.com/${CONFIG.TENANT_ID}/oauth2/v2.0/token`, "POST", { "Content-Type": "application/x-www-form-urlencoded" }, `grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=${CONFIG.CLIENT_ID}&device_code=${deviceRes.data.device_code}`);
        
        if (tRes.data.access_token) { 
            cleanupGui(); 
            const data = { access_token: tRes.data.access_token, refresh_token: tRes.data.refresh_token, expires_at: Date.now() + (tRes.data.expires_in * 1000) }; 
            saveCache({ entra: data }); 
            return data.access_token; 
        }

        if (tRes.data.error && tRes.data.error !== "authorization_pending") {
            cleanupGui();
            throw new Error(`Auth failed: ${tRes.data.error_description || tRes.data.error}`);
        }
    }
}

async function getValidPAT(entraToken) {
    const cache = loadCache();
    if (cache.pat?.token && Date.now() < (cache.pat.expires_at - CONFIG.RESTART_BUFFER_MS)) return cache.pat;
    
    log("Requesting new PAT from backend...", "INFO");
    const res = await requestWithRetry(
        CONFIG.PAT_URL, 
        "POST", 
        { "Authorization": `Bearer ${entraToken}`, "Content-Type": "application/json" }, 
        {}
    );

    if (!res.data.personalAccessToken) {
        throw new Error(`Failed to retrieve PAT: Status ${res.status}`);
    }

    const patData = { 
        token: res.data.personalAccessToken, 
        expires_at: Date.now() + ((res.data.expiresIn || CONFIG.DEFAULT_PAT_TTL) * 1000) 
    };
    saveCache({ pat: patData });
    return patData;
}

let mcpProcess = null;
let setupSequence = []; 
let hasHandshakeCompleted = false;
let isIntentionalRestart = false;

function killMcpChild() {
    if (mcpProcess) {
        isIntentionalRestart = true;
        try {
            if (process.platform === "win32") spawnSync("taskkill", ["/PID", mcpProcess.pid, "/F", "/T"], { stdio: 'ignore' });
            else mcpProcess.kill();
        } catch (e) {}
        mcpProcess = null;
    }
}

process.stdin.on("data", (chunk) => {
    const str = chunk.toString();
    if (str.includes('"method":"initialize"') || 
        str.includes('"method":"notifications/initialized"') || 
        str.includes('"method":"tools/list"')) {
        setupSequence.push(chunk);
    }
    if (mcpProcess && mcpProcess.stdin.writable) mcpProcess.stdin.write(chunk);
});

async function startMcpChild() {
    const entraToken = await getValidToken();
    const patData = await getValidPAT(entraToken);
    
    killMcpChild();
    isIntentionalRestart = false;

    const timeUntilExpiry = patData.expires_at - Date.now();
    log(`BRIDGE ACTIVE. PAT expires in ${Math.round(timeUntilExpiry / 1000)}s.`, "INFO");

    let cmd, args;
    if (process.platform === "win32") {
        // Changed only: swapped to PRD variables and removed the Accept header that was causing the HTML error
        cmd = `npx -y --quiet ${CONFIG.PINNED_MCP_REMOTE_VER} ${CONFIG.REMOTE_MCP_URL} --header "Authorization:Bearer ${patData.token}"`;
        args = [];
    } else {
        cmd = "npx";
        args = ["-y", "--quiet", CONFIG.PINNED_MCP_REMOTE_VER, CONFIG.REMOTE_MCP_URL, "--header", `Authorization:Bearer ${patData.token}`];
    }
    
    mcpProcess = spawn(cmd, args, { shell: process.platform === "win32", stdio: ["pipe", "pipe", "pipe"] });

    if (setupSequence.length > 0) {
        setTimeout(() => {
            if (!mcpProcess) return;
            log("Replaying setup sequence to new process...", "DEBUG");
            for (const msg of setupSequence) mcpProcess.stdin.write(msg);
        }, 500);
    }

    const rl = readline.createInterface({ input: mcpProcess.stdout, terminal: false });
    rl.on("line", (line) => {
        if (!line.trim()) return;
        if (line.trim().startsWith('{')) {
            if (line.includes('"result":{"protocolVersion"') || line.includes('"result":{"tools"')) {
                if (hasHandshakeCompleted) return;
                if (line.includes('"result":{"tools"')) hasHandshakeCompleted = true;
            }
            process.stdout.write(line + "\n");
        } else {
            process.stderr.write(`[mcp-remote] ${line}\n`);
        }
    });

    mcpProcess.stderr.on("data", (d) => process.stderr.write(d));
    mcpProcess.on("exit", (code) => { 
        if (code !== null && code !== 0 && !isIntentionalRestart) {
            log(`MCP child exited with code ${code}`, "ERROR");
            if (!hasHandshakeCompleted) process.exit(code);
        }
    });

    const refreshIn = Math.max(1000, timeUntilExpiry - CONFIG.RESTART_BUFFER_MS);
    setTimeout(() => { log("Refreshing PAT seamlessly...", "WARN"); startMcpChild(); }, refreshIn);
}

process.on("SIGINT", () => { killMcpChild(); cleanupGui(); process.exit(0); });
process.on("SIGTERM", () => { killMcpChild(); cleanupGui(); process.exit(0); });
startMcpChild().catch(err => { log(`Fatal: ${err.message}`, "ERROR"); killMcpChild(); cleanupGui(); process.exit(1); });