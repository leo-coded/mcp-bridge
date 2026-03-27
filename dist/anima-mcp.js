#!/usr/bin/env node

/**
 * @file anima-mcp-bridge.js
 * @description Bridge between Microsoft Entra ID and Anima MCP Server.
 * @version 1.0.4 (Fixed Token Lifecycle & Spawning)
 * @license GPL-3.0
 */

const { spawn, spawnSync, execSync } = require("child_process");
const https = require("https");
const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");

const CONFIG = {
    TENANT_ID: process.env.ANIMA_TENANT_ID || "80f6a699-b024-4b7b-8cca-5ecfdd2a2fe3",
    CLIENT_ID: process.env.ANIMA_CLIENT_ID || "768e71b3-d619-42d1-b382-ef2d5b921821",
    API_SCOPE: "api://servico_hackathon_mcp_devhml/Api.Read",
    PAT_URL: process.env.ANIMA_PAT_URL || "https://cloudapp-dev.animaeducacao.com.br/servico-hackathon-mcp/auth/pats",
    REMOTE_MCP_URL: process.env.ANIMA_MCP_URL || "https://cloudapp-dev.animaeducacao.com.br/servico-hackathon-mcp/mcp",
    CACHE_PATH: path.join(os.homedir(), ".anima-mcp-cache.enc"),
    WINDOW_TITLE: "AnimaMCPAuth",
    USER_AGENT: "Anima-MCP-Bridge/1.0.4",
    PINNED_MCP_REMOTE_VER: "mcp-remote@0.1.3",
    REQUEST_TIMEOUT: 15000,
    MAX_AUTH_POLLING_SEC: 900,
    DEFAULT_PAT_TTL: 900
};

const ALLOWED_HOSTS = [
    "login.microsoftonline.com",
    "cloudapp-dev.animaeducacao.com.br"
];

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
    const authTag = cipher.getAuthTag().toString('hex');
    return `${iv.toString('hex')}:${authTag}:${encrypted}`;
}

function decrypt(cipherText) {
    try {
        const [ivHex, authTagHex, encrypted] = cipherText.split(':');
        const decipher = crypto.createDecipheriv('aes-256-gcm', getEncryptionKey(), Buffer.from(ivHex, 'hex'));
        decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (e) { return null; }
}

let activeGuiProcess = null;

function cleanup() {
    if (!activeGuiProcess) return;
    try {
        if (process.platform === "win32") {
            spawnSync("taskkill", ["/FI", `WINDOWTITLE eq ${CONFIG.WINDOW_TITLE}*`, "/F", "/T"], { stdio: 'ignore' });
        } else {
            activeGuiProcess.kill('SIGTERM');
        }
    } catch (e) { }
}

process.on("SIGINT", cleanup);
process.on("SIGTERM", cleanup);

function showAuthGui(userCode, verificationUri) {
    const platform = process.platform;
    if (platform === "win32") {
        const xaml = `
        <Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                Title="${CONFIG.WINDOW_TITLE}" Width="480" SizeToContent="Height" 
                WindowStartupLocation="CenterScreen" Background="#F3F3F3" ResizeMode="NoResize" Topmost="True">
            <StackPanel Margin="30,30,30,40">
                <TextBlock Text="Connect to Anima MCP" FontSize="22" FontWeight="Bold" Margin="0,0,0,10"/>
                <TextBlock Text="Please authenticate with your student credentials." TextWrapping="Wrap" Margin="0,0,0,25"/>
                <Border Background="White" BorderBrush="#DDDDDD" BorderThickness="1" CornerRadius="5" Padding="20">
                    <TextBlock Text="${userCode}" FontSize="32" FontWeight="ExtraBold" HorizontalAlignment="Center" Foreground="#0078D4"/>
                </Border>
                <Grid Margin="0,30,0,0">
                    <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                    <Button Name="CopyBtn" Content="Copy Code" Grid.Column="0" Margin="0,0,8,0" Height="40"/>
                    <Button Name="LaunchBtn" Content="Open Browser" Grid.Column="1" Margin="8,0,0,0" Height="40" Background="#0078D4" Foreground="White"/>
                </Grid>
            </StackPanel>
        </Window>`;
        const xamlBase64 = Buffer.from(xaml).toString('base64');
        const psScript = `
            Add-Type -AssemblyName PresentationFramework;
            $window = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader ([xml][System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('${xamlBase64}')))));
            $window.FindName('CopyBtn').Add_Click({ Set-Clipboard -Value '${userCode}' });
            $window.FindName('LaunchBtn').Add_Click({ Set-Clipboard -Value '${userCode}'; Start-Process '${verificationUri}'; });
            Set-Clipboard -Value '${userCode}';
            $window.ShowDialog() | Out-Null;
        `.replace(/\n/g, ' ');
        activeGuiProcess = spawn("powershell.exe", ["-NoProfile", "-Command", psScript]);
    } 
    else if (platform === "darwin") {
        const appleScript = `
            set theCode to "${userCode}"
            set the clipboard to theCode
            display dialog "To connect to Anima MCP, use this code in your browser:\\n\\n" & theCode & "\\n\\nThe code has been copied to your clipboard." with title "Anima MCP Auth" buttons {"Open Browser", "Cancel"} default button "Open Browser"
            if button returned of result is "Open Browser" then
                open location "${verificationUri}"
            end if
        `;
        activeGuiProcess = spawn("osascript", ["-e", appleScript]);
    } 
    else {
        log(`\n=== AUTH REQUIRED ===\nCODE: ${userCode}\nURL: ${verificationUri}\n====================\n`, "WARN");
    }
}

function askConsent() {
    if (process.platform === "win32") {
        const psScript = `Add-Type -AssemblyName PresentationFramework; $res = [System.Windows.MessageBox]::Show('Connect to Anima MCP?', 'Anima MCP', 'YesNo', 'Information'); if ($res -eq 'Yes') { exit 0 } else { exit 1 }`;
        return spawnSync("powershell.exe", ["-NoProfile", "-Command", psScript]).status === 0;
    } else if (process.platform === "darwin") {
        try {
            execSync(`osascript -e 'display dialog "Connect to Anima MCP?" with title "Anima MCP" buttons {"No", "Yes"} default button "Yes"'`);
            return true;
        } catch (e) { return false; }
    }
    return true; 
}

function request(url, method, headers, body) {
    return new Promise((resolve) => {
        const urlObj = new URL(url);
        if (!ALLOWED_HOSTS.includes(urlObj.hostname)) {
            log(`Blocked request to unauthorized host: ${urlObj.hostname}`, "ERROR");
            return resolve({ status: 403, data: { error: "Security validation failed" } });
        }

        const payload = typeof body === "string" ? body : JSON.stringify(body);
        const options = {
            method,
            headers: { ...headers, "Content-Length": Buffer.byteLength(payload), "User-Agent": CONFIG.USER_AGENT },
            timeout: CONFIG.REQUEST_TIMEOUT
        };

        const req = https.request(url, options, (res) => {
            let data = "";
            res.on("data", (chunk) => (data += chunk));
            res.on("end", () => {
                try { resolve({ status: res.statusCode, data: JSON.parse(data || "{}") }); }
                catch (e) { resolve({ status: res.statusCode, data: { raw: data.substring(0, 100) } }); }
            });
        });

        req.on("timeout", () => { req.destroy(); resolve({ status: 408, data: { error: "Timeout" } }); });
        req.on("error", (e) => resolve({ status: 500, data: { error: e.message } }));
        req.write(payload);
        req.end();
    });
}

function loadCache() {
    if (fs.existsSync(CONFIG.CACHE_PATH)) {
        try {
            const encryptedData = fs.readFileSync(CONFIG.CACHE_PATH, "utf8");
            const decrypted = decrypt(encryptedData);
            if (decrypted) return JSON.parse(decrypted);
        } catch (e) { log("Cache read error.", "WARN"); }
    }
    return {};
}

function saveCache(data) {
    try {
        const existing = loadCache();
        const updated = { ...existing, ...data };
        fs.writeFileSync(CONFIG.CACHE_PATH, encrypt(JSON.stringify(updated)));
    } catch (e) { log("Cache write error.", "ERROR"); }
}

async function getValidToken() {
    const cache = loadCache();
    if (cache.entra && cache.entra.access_token && Date.now() < (cache.entra.expires_at - 60000)) {
        return cache.entra.access_token;
    }

    if (!askConsent()) throw new Error("User declined authentication.");

    const deviceRes = await request(`https://login.microsoftonline.com/${CONFIG.TENANT_ID}/oauth2/v2.0/devicecode`, "POST", 
        { "Content-Type": "application/x-www-form-urlencoded" }, 
        `client_id=${CONFIG.CLIENT_ID}&scope=${encodeURIComponent(CONFIG.API_SCOPE + " offline_access openid profile")}`
    );

    if (!deviceRes.data.user_code) throw new Error("Microsoft Entra ID communication failure.");

    showAuthGui(deviceRes.data.user_code, "https://login.microsoftonline.com/common/oauth2/deviceauth");
    log(`Awaiting authentication (Code: ${deviceRes.data.user_code})...`);
    
    const startTime = Date.now();
    while (true) {
        if ((Date.now() - startTime) / 1000 > CONFIG.MAX_AUTH_POLLING_SEC) {
            cleanup();
            throw new Error("Authentication timed out.");
        }
        await new Promise(r => setTimeout(r, 5000));
        const tokenRes = await request(`https://login.microsoftonline.com/${CONFIG.TENANT_ID}/oauth2/v2.0/token`, "POST",
            { "Content-Type": "application/x-www-form-urlencoded" },
            `grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=${CONFIG.CLIENT_ID}&device_code=${deviceRes.data.device_code}`
        );

        if (tokenRes.data.access_token) {
            cleanup();
            const entraData = { 
                access_token: tokenRes.data.access_token, 
                expires_at: Date.now() + (tokenRes.data.expires_in * 1000) 
            };
            saveCache({ entra: entraData });
            log("Microsoft authentication successful.", "AUDIT");
            return tokenRes.data.access_token;
        }
        if (tokenRes.data.error !== "authorization_pending") {
            cleanup();
            throw new Error(tokenRes.data.error_description || "Auth failed.");
        }
    }
}

async function getValidPAT(entraToken) {
    const cache = loadCache();
    if (cache.pat && cache.pat.token && Date.now() < (cache.pat.expires_at - 30000)) {
        return cache.pat;
    }

    log("Requesting new PAT from backend...", "INFO");
    const patRes = await request(CONFIG.PAT_URL, "POST", { 
        "Authorization": `Bearer ${entraToken}`, 
        "Content-Type": "application/json" 
    }, {});

    const token = patRes.data.personalAccessToken;
    if (!token) throw new Error(`Backend returned ${patRes.status}. Check permissions.`);

    const ttlSeconds = patRes.data.expiresIn || patRes.data.ttlSeconds || CONFIG.DEFAULT_PAT_TTL;
    const patData = {
        token: token,
        expires_at: Date.now() + (ttlSeconds * 1000)
    };

    saveCache({ pat: patData });
    return patData;
}

async function start() {
    try {
        const entraToken = await getValidToken();
        const patData = await getValidPAT(entraToken);

        log(`BRIDGE ACTIVE. PAT expires in ${Math.round((patData.expires_at - Date.now()) / 1000)}s.`, "INFO");
        
        const timeUntilExpiry = patData.expires_at - Date.now();
        const exitBuffer = 30000; 
        
        if (timeUntilExpiry > exitBuffer) {
            setTimeout(() => {
                log("PAT approaching expiration. Restarting bridge to refresh token...", "WARN");
                process.exit(0); 
            }, timeUntilExpiry - exitBuffer);
        }

        let mcp;
        if (process.platform === "win32") {
            // Restored original spawning logic for Windows
            const cmd = `npx -y --quiet ${CONFIG.PINNED_MCP_REMOTE_VER} ${CONFIG.REMOTE_MCP_URL} --header "Authorization: Bearer ${patData.token}" --header "Accept: application/json"`;
            mcp = spawn(cmd, [], { 
                shell: true, 
                stdio: ["inherit", "inherit", "pipe"],
                env: { ...process.env, NO_UPDATE_NOTIFIER: "true" }
            });
        } else {
            const args = ["-y", "--quiet", CONFIG.PINNED_MCP_REMOTE_VER, CONFIG.REMOTE_MCP_URL, "--header", `Authorization: Bearer ${patData.token}`, "--header", "Accept: application/json"];
            mcp = spawn("npx", args, { stdio: ["inherit", "inherit", "pipe"] });
        }

        mcp.stderr.on("data", (d) => process.stderr.write(d));
        mcp.on("error", (err) => {
            log(`Failed to start MCP: ${err.message}`, "ERROR");
            process.exit(1);
        });
        mcp.on("exit", (code) => {
            log(`MCP exited with code ${code}`, "INFO");
            process.exit(code || 0);
        });

    } catch (err) {
        log(`Fatal Error: ${err.message}`, "ERROR");
        cleanup();
        process.exit(1);
    }
}

start();