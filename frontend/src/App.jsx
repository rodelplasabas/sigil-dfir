import { useState, useCallback, useRef, useEffect, Fragment } from "react";

// ═══════════════════════════════════════════════════════════════════════════════
// DFIR COMPROMISE ASSESSMENT TOOL — "SIGIL"
// Open-source triage assistant for incident responders
// ═══════════════════════════════════════════════════════════════════════════════

// ─── LATERAL MOVEMENT EVENT ID CATEGORIES ────────────────────────────────────
const LM_EVENT_CATEGORIES = [
  { name: "Logon Activity", icon: "🔐", desc: "Critical for lateral movement detection", eids: [
    { id: "4624", label: "Successful Logon", hint: "Focus on Type 3 (Network) and Type 10 (RDP)", sev: "high" },
    { id: "4625", label: "Failed Logon", hint: "Brute force attempts before lateral movement", sev: "high" },
    { id: "4634", label: "Logoff", hint: "Session ended", sev: "low" },
    { id: "4647", label: "User-Initiated Logoff", hint: "User logoff event", sev: "low" },
    { id: "4648", label: "Explicit Credentials (RunAs)", hint: "PsExec, RunAs, Pass-the-Hash", sev: "critical" },
  ]},
  { name: "Privilege & Token Abuse", icon: "🔑", desc: "Privilege escalation indicators", eids: [
    { id: "4672", label: "Special Privileges Assigned", hint: "Admin-level logon", sev: "high" },
    { id: "4673", label: "Sensitive Privilege Use", hint: "Privileged service called", sev: "medium" },
    { id: "4674", label: "Privileged Object Operation", hint: "Privileged operation attempted", sev: "medium" },
  ]},
  { name: "Kerberos Authentication", icon: "🎫", desc: "Pass-the-Ticket, Kerberoasting", eids: [
    { id: "4768", label: "Kerberos TGT Request", hint: "Ticket Granting Ticket requested", sev: "medium" },
    { id: "4769", label: "Kerberos Service Ticket", hint: "Spikes may indicate Kerberoasting", sev: "high" },
    { id: "4776", label: "NTLM Authentication", hint: "NTLM credential validation", sev: "medium" },
  ]},
  { name: "Service & Task Creation", icon: "⚙️", desc: "Remote execution via services", eids: [
    { id: "7045", label: "Service Installed (System)", hint: "Classic PsExec-style indicator", sev: "critical" },
    { id: "4697", label: "Service Installed (Security)", hint: "Service installation logged", sev: "high" },
    { id: "4698", label: "Scheduled Task Created", hint: "Remote scheduled task creation", sev: "high" },
    { id: "4702", label: "Scheduled Task Updated", hint: "Task modified", sev: "medium" },
  ]},
  { name: "SMB / File Share Access", icon: "📁", desc: "Network share movement", eids: [
    { id: "5140", label: "Network Share Accessed", hint: "Share object accessed", sev: "medium" },
    { id: "5145", label: "Detailed Share Access", hint: "ADMIN$ and C$ access detection", sev: "high" },
  ]},
  { name: "Process Creation", icon: "🚀", desc: "Suspicious process execution", eids: [
    { id: "4688", label: "New Process Created", hint: "Correlate with cmd.exe, powershell.exe, psexecsvc.exe", sev: "high" },
  ]},
  { name: "PowerShell", icon: "⚡", desc: "Remote commands and encoded payloads", eids: [
    { id: "4103", label: "Module Logging", hint: "PowerShell module loaded", sev: "medium" },
    { id: "4104", label: "Script Block Logging", hint: "Script content captured", sev: "high" },
  ]},
  { name: "WMI Execution", icon: "🌐", desc: "Stealthy lateral movement", eids: [
    { id: "5861", label: "WMI Activity", hint: "WMI-Activity log event", sev: "high" },
  ]},
  { name: "RDP Session Lifecycle", icon: "🖥️", desc: "Full RDP session tracking", eids: [
    { id: "1149", label: "Network Authentication", hint: "TerminalServices-RemoteConnectionManager", sev: "high" },
    { id: "21", label: "Session Logon", hint: "LocalSessionManager", sev: "medium" },
    { id: "22", label: "Shell Start", hint: "Shell ready", sev: "low" },
    { id: "23", label: "Session Logoff", hint: "RDP session ended", sev: "low" },
    { id: "24", label: "Session Disconnected", hint: "Disconnected (may persist)", sev: "low" },
    { id: "25", label: "Session Reconnected", hint: "Reconnected to existing session", sev: "medium" },
    { id: "39", label: "Disconnect by Other", hint: "Session disconnected by another", sev: "low" },
    { id: "40", label: "Disconnect Reason", hint: "Disconnect with reason code", sev: "low" },
    { id: "4778", label: "Session Reconnected (Security)", hint: "Window Station reconnect", sev: "medium" },
    { id: "4779", label: "Session Disconnected (Security)", hint: "Window Station disconnect", sev: "medium" },
  ]},
  { name: "Sysmon (If Enabled)", icon: "🔍", desc: "High-value endpoint telemetry", eids: [
    { id: "1", label: "Process Creation", hint: "Sysmon process create with command line", sev: "high" },
    { id: "3", label: "Network Connection", hint: "Outbound network connections", sev: "medium" },
    { id: "10", label: "Process Access", hint: "Credential dumping precursor (LSASS)", sev: "critical" },
    { id: "11", label: "File Creation", hint: "New files written to disk", sev: "medium" },
    { id: "22", label: "DNS Query", hint: "DNS resolution logged", sev: "low" },
  ]},
];

// ─── MITRE ATT&CK TECHNIQUE DATABASE ─────────────────────────────────────────
const MITRE_TECHNIQUES = {
  T1078: { id: "T1078", name: "Valid Accounts", tactic: "Initial Access, Persistence", url: "https://attack.mitre.org/techniques/T1078/" },
  T1059: { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution", url: "https://attack.mitre.org/techniques/T1059/" },
  T1053: { id: "T1053", name: "Scheduled Task/Job", tactic: "Execution, Persistence", url: "https://attack.mitre.org/techniques/T1053/" },
  T1547: { id: "T1547", name: "Boot or Logon Autostart Execution", tactic: "Persistence", url: "https://attack.mitre.org/techniques/T1547/" },
  T1136: { id: "T1136", name: "Create Account", tactic: "Persistence", url: "https://attack.mitre.org/techniques/T1136/" },
  T1548: { id: "T1548", name: "Abuse Elevation Control Mechanism", tactic: "Privilege Escalation", url: "https://attack.mitre.org/techniques/T1548/" },
  T1055: { id: "T1055", name: "Process Injection", tactic: "Defense Evasion", url: "https://attack.mitre.org/techniques/T1055/" },
  T1070: { id: "T1070", name: "Indicator Removal", tactic: "Defense Evasion", url: "https://attack.mitre.org/techniques/T1070/" },
  T1562: { id: "T1562", name: "Impair Defenses", tactic: "Defense Evasion", url: "https://attack.mitre.org/techniques/T1562/" },
  T1110: { id: "T1110", name: "Brute Force", tactic: "Credential Access", url: "https://attack.mitre.org/techniques/T1110/" },
  T1003: { id: "T1003", name: "OS Credential Dumping", tactic: "Credential Access", url: "https://attack.mitre.org/techniques/T1003/" },
  T1018: { id: "T1018", name: "Remote System Discovery", tactic: "Discovery", url: "https://attack.mitre.org/techniques/T1018/" },
  T1021: { id: "T1021", name: "Remote Services", tactic: "Lateral Movement", url: "https://attack.mitre.org/techniques/T1021/" },
  T1105: { id: "T1105", name: "Ingress Tool Transfer", tactic: "Command and Control", url: "https://attack.mitre.org/techniques/T1105/" },
  T1071: { id: "T1071", name: "Application Layer Protocol", tactic: "Command and Control", url: "https://attack.mitre.org/techniques/T1071/" },
  T1190: { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access", url: "https://attack.mitre.org/techniques/T1190/" },
  T1505: { id: "T1505", name: "Server Software Component", tactic: "Persistence", url: "https://attack.mitre.org/techniques/T1505/" },
  T1027: { id: "T1027", name: "Obfuscated Files or Information", tactic: "Defense Evasion", url: "https://attack.mitre.org/techniques/T1027/" },
  T1486: { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact", url: "https://attack.mitre.org/techniques/T1486/" },
  T1490: { id: "T1490", name: "Inhibit System Recovery", tactic: "Impact", url: "https://attack.mitre.org/techniques/T1490/" },
  T1112: { id: "T1112", name: "Modify Registry", tactic: "Defense Evasion", url: "https://attack.mitre.org/techniques/T1112/" },
  T1543: { id: "T1543", name: "Create or Modify System Process", tactic: "Persistence, Privilege Escalation", url: "https://attack.mitre.org/techniques/T1543/" },
  T1569: { id: "T1569", name: "System Services", tactic: "Execution", url: "https://attack.mitre.org/techniques/T1569/" },
  T1546: { id: "T1546", name: "Event Triggered Execution", tactic: "Persistence, Privilege Escalation", url: "https://attack.mitre.org/techniques/T1546/" },
  T1083: { id: "T1083", name: "File and Directory Discovery", tactic: "Discovery", url: "https://attack.mitre.org/techniques/T1083/" },
};


function severityWeight(s) {
  return { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[s] || 0;
}

function computeOverallScore(findings) {
  if (findings.length === 0) return { label: "CLEAN", color: "#10b981", score: 0 };
  const maxSev = Math.max(...findings.map(f => severityWeight(f.severity)));
  const critCount = findings.filter(f => f.severity === "critical").length;
  const highCount = findings.filter(f => f.severity === "high").length;
  const totalWeight = findings.reduce((sum, f) => sum + severityWeight(f.severity) * f.confidence, 0);
  if (critCount >= 2 || totalWeight > 500) return { label: "COMPROMISED", color: "#ef4444", score: totalWeight };
  if (critCount >= 1 || highCount >= 2 || totalWeight > 200) return { label: "SUSPICIOUS", color: "#f59e0b", score: totalWeight };
  if (maxSev >= 2 || totalWeight > 80) return { label: "SUSPICIOUS", color: "#f59e0b", score: totalWeight };
  return { label: "CLEAN", color: "#10b981", score: totalWeight };
}

// ─── ICONS ──────────────────────────────────────────────────────────────────
const Icons = {
  Shield: () => (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
  ),
  Upload: () => (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
  ),
  AlertTriangle: () => (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
  ),
  Check: () => (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
  ),
  File: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
  ),
  Search: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
  ),
  ChevronDown: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="6 9 12 15 18 9"/></svg>
  ),
  Target: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>
  ),
  ExternalLink: () => (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
  ),
  Download: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
  ),
  Clipboard: () => (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><rect x="8" y="2" width="8" height="4" rx="1" ry="1"/></svg>
  ),
  Trash: () => (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
  ),
  Info: () => (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
  ),
};

// ─── STYLES ─────────────────────────────────────────────────────────────────
const FONT_IMPORT = `@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Outfit:wght@300;400;500;600;700;800;900&display=swap');`;

const STYLES = `
  ${FONT_IMPORT}

  :root {
    --bg-primary: #0a0e17;
    --bg-secondary: #111827;
    --bg-tertiary: #1a2235;
    --bg-card: #151d2e;
    --bg-card-hover: #1a2540;
    --border-primary: #1e293b;
    --border-accent: #2563eb30;
    --text-primary: #e2e8f0;
    --text-secondary: #94a3b8;
    --text-muted: #64748b;
    --accent-blue: #3b82f6;
    --accent-blue-dim: #3b82f640;
    --accent-cyan: #06b6d4;
    --accent-red: #ef4444;
    --accent-orange: #f59e0b;
    --accent-green: #10b981;
    --accent-purple: #8b5cf6;
    --severity-critical: #ef4444;
    --severity-high: #f97316;
    --severity-medium: #eab308;
    --severity-low: #3b82f6;
    --severity-info: #64748b;
    --radius: 8px;
    --radius-lg: 12px;
    --font-display: 'Outfit', sans-serif;
    --font-mono: 'JetBrains Mono', monospace;
    --glow-blue: 0 0 20px #3b82f620, 0 0 60px #3b82f610;
    --glow-red: 0 0 20px #ef444420, 0 0 60px #ef444410;
    --glow-green: 0 0 20px #10b98120, 0 0 60px #10b98110;
  }

  * { margin: 0; padding: 0; box-sizing: border-box; }

  body, #root {
    background: var(--bg-primary);
    color: var(--text-primary);
    font-family: var(--font-display);
    min-height: 100vh;
    -webkit-font-smoothing: antialiased;
  }

  .app-container {
    max-width: 1400px;
    margin: 0 auto;
    padding: 24px 20px;
    min-height: 100vh;
  }

  /* ── Header ───────────────────── */
  .header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 20px 0 28px;
    border-bottom: 1px solid var(--border-primary);
    margin-bottom: 28px;
  }
  .header-left { display: flex; align-items: center; gap: 16px; }
  .logo-mark {
    width: 48px; height: 48px;
    background: linear-gradient(135deg, var(--accent-blue), var(--accent-cyan));
    border-radius: 14px;
    display: flex; align-items: center; justify-content: center;
    color: white;
    box-shadow: var(--glow-blue);
    position: relative;
    overflow: hidden;
  }
  .logo-mark::after {
    content: '';
    position: absolute; inset: 0;
    background: linear-gradient(135deg, transparent 40%, rgba(255,255,255,0.15) 50%, transparent 60%);
    animation: logoShine 3s ease-in-out infinite;
  }
  @keyframes logoShine { 0%,100%{transform:translateX(-100%)} 50%{transform:translateX(100%)} }
  .brand-text h1 {
    font-family: var(--font-display);
    font-weight: 800;
    font-size: 22px;
    letter-spacing: -0.5px;
    background: linear-gradient(135deg, var(--text-primary), var(--accent-cyan));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }
  .brand-text p {
    font-size: 12px;
    color: var(--text-muted);
    font-family: var(--font-mono);
    font-weight: 400;
    letter-spacing: 0.5px;
  }
  .version-badge {
    font-family: var(--font-mono);
    font-size: 11px;
    padding: 4px 10px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border-primary);
    border-radius: 20px;
    color: var(--text-muted);
  }

  /* ── Upload Zone ─────────────── */
  .upload-zone {
    border: 2px dashed var(--border-primary);
    border-radius: var(--radius-lg);
    padding: 48px 24px;
    text-align: center;
    cursor: pointer;
    transition: all 0.3s ease;
    background: var(--bg-secondary);
    position: relative;
    overflow: hidden;
  }
  .upload-zone::before {
    content: '';
    position: absolute; inset: 0;
    background: radial-gradient(circle at 50% 50%, var(--accent-blue-dim) 0%, transparent 70%);
    opacity: 0;
    transition: opacity 0.3s;
  }
  .upload-zone:hover { border-color: var(--accent-blue); }
  .upload-zone:hover::before { opacity: 1; }
  .upload-zone.dragover {
    border-color: var(--accent-cyan);
    background: #0e1a2d;
    box-shadow: var(--glow-blue);
  }
  .upload-icon {
    width: 64px; height: 64px;
    margin: 0 auto 16px;
    background: var(--bg-tertiary);
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    color: var(--accent-blue);
    position: relative;
    z-index: 1;
  }
  .upload-text { position: relative; z-index: 1; }
  .upload-text h3 { font-size: 16px; font-weight: 600; margin-bottom: 8px; }
  .upload-text p { font-size: 13px; color: var(--text-muted); }
  .supported-types {
    display: flex; gap: 8px; justify-content: center;
    margin-top: 16px; flex-wrap: wrap; position: relative; z-index: 1;
  }
  .type-badge {
    font-family: var(--font-mono);
    font-size: 11px;
    padding: 3px 10px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border-primary);
    border-radius: 4px;
    color: var(--text-secondary);
  }

  .paste-area {
    margin-top: 16px;
    position: relative; z-index: 1;
  }
  .paste-toggle {
    font-size: 12px;
    color: var(--accent-blue);
    background: none; border: none; cursor: pointer;
    font-family: var(--font-mono);
    padding: 4px 8px;
  }
  .paste-toggle:hover { text-decoration: underline; }
  .paste-input {
    width: 100%; margin-top: 8px;
    background: var(--bg-primary);
    border: 1px solid var(--border-primary);
    border-radius: var(--radius);
    padding: 12px;
    color: var(--text-primary);
    font-family: var(--font-mono);
    font-size: 12px;
    min-height: 150px;
    resize: vertical;
  }
  .paste-input:focus { outline: none; border-color: var(--accent-blue); }
  .paste-actions {
    display: flex; gap: 8px; justify-content: flex-end; margin-top: 8px;
  }

  /* ── Buttons ──────────────────── */
  .btn {
    padding: 8px 16px;
    border-radius: var(--radius);
    font-family: var(--font-display);
    font-weight: 500;
    font-size: 13px;
    cursor: pointer;
    transition: all 0.2s ease;
    border: 1px solid transparent;
    display: inline-flex; align-items: center; gap: 6px;
  }
  .btn-primary {
    background: var(--accent-blue);
    color: white;
    border-color: var(--accent-blue);
  }
  .btn-primary:hover { background: #2563eb; box-shadow: var(--glow-blue); }
  .btn-secondary {
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    border-color: var(--border-primary);
  }
  .btn-secondary:hover { color: var(--text-primary); border-color: var(--text-muted); }
  .btn-ghost {
    background: transparent;
    color: var(--text-secondary);
    border: none; padding: 6px 10px;
  }
  .btn-ghost:hover { color: var(--text-primary); background: var(--bg-tertiary); }
  .btn-danger {
    background: transparent;
    color: var(--accent-red);
    border-color: #ef444440;
  }
  .btn-danger:hover { background: #ef444415; }

  /* ── Artifacts Panel ────────── */
  .artifacts-panel {
    background: var(--bg-card);
    border: 1px solid var(--border-primary);
    border-radius: var(--radius-lg);
    margin-top: 16px;
    overflow: hidden;
  }
  .artifacts-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 12px 16px;
    cursor: pointer;
    user-select: none;
    transition: background 0.2s;
  }
  .artifacts-header:hover { background: var(--bg-card-hover); }
  .artifacts-header-left { display: flex; align-items: center; gap: 10px; }
  .artifacts-count {
    font-family: var(--font-mono);
    font-size: 12px;
    font-weight: 600;
    background: var(--accent-blue);
    color: white;
    padding: 2px 8px;
    border-radius: 10px;
    min-width: 24px;
    text-align: center;
  }
  .artifacts-header-title { font-size: 13px; font-weight: 600; }
  .artifacts-summary {
    display: flex; align-items: center; gap: 12px;
    font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);
  }
  .artifacts-summary-dot {
    width: 6px; height: 6px; border-radius: 50%; display: inline-block;
  }
  .artifacts-header-right { display: flex; align-items: center; gap: 8px; }
  .artifacts-clear-btn {
    font-size: 11px; padding: 3px 8px;
    background: transparent; border: 1px solid #ef444430;
    border-radius: 4px; color: var(--accent-red);
    cursor: pointer; font-family: var(--font-mono);
    transition: all 0.2s;
  }
  .artifacts-clear-btn:hover { background: #ef444415; }
  .artifacts-body {
    border-top: 1px solid var(--border-primary);
    max-height: 280px;
    overflow-y: auto;
    padding: 8px;
  }
  .loaded-files {
    display: flex; flex-wrap: wrap; gap: 8px;
  }
  .file-chip {
    display: inline-flex; align-items: center; gap: 8px;
    padding: 6px 12px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border-primary);
    border-radius: 20px;
    font-size: 12px;
    font-family: var(--font-mono);
  }
  .file-chip .type-indicator {
    width: 8px; height: 8px; border-radius: 50%;
  }
  .file-chip button {
    background: none; border: none;
    color: var(--text-muted); cursor: pointer; padding: 0; display: flex;
  }
  .file-chip button:hover { color: var(--accent-red); }

  /* ── Analysis Controls ────────── */
  .analysis-controls {
    display: flex; align-items: center; justify-content: space-between;
    margin: 20px 0;
    flex-wrap: wrap; gap: 12px;
  }
  .run-btn {
    padding: 12px 28px;
    font-size: 14px;
    font-weight: 700;
    letter-spacing: 0.3px;
    text-transform: uppercase;
    background: linear-gradient(135deg, var(--accent-blue), var(--accent-cyan));
    border: none;
    border-radius: var(--radius);
    color: white;
    cursor: pointer;
    transition: all 0.3s ease;
    position: relative;
    overflow: hidden;
  }
  .run-btn:hover { box-shadow: var(--glow-blue); transform: translateY(-1px); }
  .run-btn:active { transform: translateY(0); }
  .run-btn:disabled { opacity: 0.4; cursor: not-allowed; transform: none; }
  .run-btn::after {
    content: ''; position: absolute; inset: 0;
    background: linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent);
    transform: translateX(-100%);
  }
  .run-btn:hover::after { animation: shimmer 1.5s ease forwards; }
  @keyframes shimmer { to { transform: translateX(100%); } }

  /* ── Score Banner ─────────────── */
  .score-banner {
    display: flex; align-items: center; justify-content: space-between;
    padding: 20px 24px;
    border-radius: var(--radius-lg);
    margin-bottom: 24px;
    position: relative;
    overflow: hidden;
    border: 1px solid;
  }
  .score-banner.clean { background: #10b98108; border-color: #10b98130; }
  .score-banner.suspicious { background: #f59e0b08; border-color: #f59e0b30; }
  .score-banner.compromised { background: #ef444408; border-color: #ef444430; }
  .score-label {
    font-size: 28px; font-weight: 800;
    letter-spacing: 2px;
    font-family: var(--font-display);
  }
  .score-details { text-align: right; }
  .score-details p { font-size: 13px; color: var(--text-secondary); }
  .score-details .count { font-family: var(--font-mono); font-weight: 600; }
  .score-banner .pulse {
    position: absolute; left: 24px; top: 50%; transform: translateY(-50%);
    width: 12px; height: 12px; border-radius: 50%;
  }
  .score-banner.compromised .pulse {
    background: var(--accent-red);
    box-shadow: 0 0 8px var(--accent-red);
    animation: pulsate 1.5s ease-in-out infinite;
  }
  .score-banner.suspicious .pulse {
    background: var(--accent-orange);
    box-shadow: 0 0 8px var(--accent-orange);
    animation: pulsate 2s ease-in-out infinite;
  }
  .score-banner.clean .pulse {
    background: var(--accent-green);
    box-shadow: 0 0 8px var(--accent-green);
  }
  @keyframes pulsate {
    0%, 100% { opacity: 1; transform: translateY(-50%) scale(1); }
    50% { opacity: 0.5; transform: translateY(-50%) scale(1.3); }
  }

  /* ── Stats Grid ───────────────── */
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 12px;
    margin-bottom: 24px;
  }
  .stat-card {
    background: var(--bg-card);
    border: 1px solid var(--border-primary);
    border-radius: var(--radius);
    padding: 16px;
    text-align: center;
  }
  .stat-card .stat-value {
    font-family: var(--font-mono);
    font-size: 28px;
    font-weight: 700;
  }
  .stat-card .stat-label {
    font-size: 11px;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-top: 4px;
  }

  /* ── Findings ─────────────────── */
  .findings-section h2 {
    font-size: 16px; font-weight: 700;
    margin-bottom: 16px;
    display: flex; align-items: center; gap: 8px;
  }

  .finding-card {
    background: var(--bg-card);
    border: 1px solid var(--border-primary);
    border-radius: var(--radius-lg);
    margin-bottom: 12px;
    overflow: hidden;
    transition: all 0.2s ease;
  }
  .finding-card:hover { border-color: var(--border-accent); background: var(--bg-card-hover); }
  .finding-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 16px 20px;
    cursor: pointer;
    user-select: none;
  }
  .finding-header-left { display: flex; align-items: center; gap: 12px; flex: 1; min-width: 0; }
  .severity-dot {
    width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0;
  }
  .severity-critical { background: var(--severity-critical); box-shadow: 0 0 6px var(--severity-critical); }
  .severity-high { background: var(--severity-high); box-shadow: 0 0 6px var(--severity-high); }
  .severity-medium { background: var(--severity-medium); box-shadow: 0 0 6px var(--severity-medium); }
  .severity-low { background: var(--severity-low); }

  .finding-title { font-weight: 600; font-size: 14px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .finding-header-right { display: flex; align-items: center; gap: 10px; flex-shrink: 0; }
  .bookmark-btn {
    background: none; border: none; cursor: pointer; padding: 2px;
    font-size: 18px; line-height: 1; transition: transform 0.15s;
    color: var(--text-muted); opacity: 0.4;
  }
  .bookmark-btn:hover { opacity: 0.8; transform: scale(1.15); }
  .bookmark-btn.active { color: var(--accent-orange); opacity: 1; }
  .severity-badge {
    font-family: var(--font-mono);
    font-size: 10px;
    font-weight: 600;
    padding: 3px 8px;
    border-radius: 4px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .badge-critical { background: #ef444420; color: var(--severity-critical); }
  .badge-high { background: #f9731620; color: var(--severity-high); }
  .badge-medium { background: #eab30820; color: var(--severity-medium); }
  .badge-low { background: #3b82f620; color: var(--severity-low); }

  .confidence-meter {
    display: flex; align-items: center; gap: 6px;
    font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);
  }
  .confidence-bar-bg {
    width: 60px; height: 4px;
    background: var(--bg-tertiary);
    border-radius: 2px; overflow: hidden;
  }
  .confidence-bar-fill { height: 100%; border-radius: 2px; transition: width 0.5s ease; }

  .chevron-icon {
    color: var(--text-muted);
    transition: transform 0.2s ease;
    flex-shrink: 0;
  }
  .chevron-icon.open { transform: rotate(180deg); }

  .finding-body {
    padding: 0 20px 20px;
    border-top: 1px solid var(--border-primary);
  }
  .finding-description {
    font-size: 13px;
    color: var(--text-secondary);
    line-height: 1.6;
    margin: 16px 0;
  }

  .detail-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
    margin-bottom: 16px;
  }
  @media (max-width: 700px) { .detail-grid { grid-template-columns: 1fr; } }

  .detail-box {
    background: var(--bg-primary);
    border: 1px solid var(--border-primary);
    border-radius: var(--radius);
    padding: 14px;
  }
  .detail-box h4 {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-muted);
    margin-bottom: 10px;
    display: flex; align-items: center; gap: 6px;
  }

  .mitre-tags { display: flex; flex-wrap: wrap; gap: 6px; }
  .mitre-tag {
    font-family: var(--font-mono);
    font-size: 11px;
    padding: 4px 10px;
    background: var(--accent-purple);
    background: #8b5cf615;
    color: var(--accent-purple);
    border: 1px solid #8b5cf630;
    border-radius: 4px;
    cursor: pointer;
    text-decoration: none;
    transition: all 0.2s;
  }
  .mitre-tag:hover { background: #8b5cf625; border-color: var(--accent-purple); }

  .match-info {
    font-family: var(--font-mono); font-size: 12px;
    color: var(--text-secondary);
  }
  .match-info span { color: var(--accent-cyan); font-weight: 600; }

  .excerpts { margin-top: 8px; }
  .excerpt {
    font-family: var(--font-mono);
    font-size: 11px;
    background: var(--bg-tertiary);
    padding: 4px 8px;
    border-radius: 3px;
    margin: 3px 0;
    color: var(--accent-orange);
    display: inline-block;
    margin-right: 4px;
    word-break: break-all;
    max-width: 100%;
  }

  .next-steps { list-style: none; }
  .next-steps li {
    font-size: 12px;
    color: var(--text-secondary);
    padding: 6px 0;
    padding-left: 20px;
    position: relative;
    line-height: 1.5;
  }
  .next-steps li::before {
    content: '→';
    position: absolute; left: 0;
    color: var(--accent-cyan);
    font-family: var(--font-mono);
  }
  .next-steps li:first-child { padding-top: 0; }

  /* ── Export ────────────────────── */
  .export-bar {
    display: flex; gap: 8px; justify-content: flex-end;
    padding: 16px 0;
    border-top: 1px solid var(--border-primary);
    margin-top: 24px;
  }

  /* ── Empty State ──────────────── */
  .empty-state {
    text-align: center;
    padding: 80px 24px;
    color: var(--text-muted);
  }
  .empty-state h3 { font-size: 18px; font-weight: 600; margin-bottom: 8px; color: var(--text-secondary); }
  .empty-state p { font-size: 13px; max-width: 400px; margin: 0 auto; line-height: 1.6; }

  /* ── Scanning Animation ──────── */
  .scanning-overlay {
    position: fixed; inset: 0;
    background: rgba(10,14,23,0.85);
    display: flex; align-items: center; justify-content: center;
    z-index: 100;
    backdrop-filter: blur(4px);
  }
  .scanning-content { text-align: center; }
  .scan-ring {
    width: 80px; height: 80px;
    border: 3px solid var(--border-primary);
    border-top-color: var(--accent-cyan);
    border-radius: 50%;
    animation: spin 1s linear infinite;
    margin: 0 auto 20px;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  .scanning-content h3 { font-size: 16px; font-weight: 600; margin-bottom: 6px; }
  .scanning-content p { font-size: 13px; color: var(--text-muted); font-family: var(--font-mono); }

  /* ── Backend Config ─────────── */
  .backend-config-toggle {
    display: flex; align-items: center; gap: 6px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border-primary);
    border-radius: 20px;
    padding: 4px 12px;
    cursor: pointer;
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--text-muted);
    transition: all 0.2s;
  }
  .backend-config-toggle:hover { border-color: var(--text-muted); color: var(--text-secondary); }
  .backend-dot {
    width: 7px; height: 7px; border-radius: 50%;
  }
  .backend-dot.ok { background: var(--accent-green); box-shadow: 0 0 4px var(--accent-green); }
  .backend-dot.error { background: var(--accent-red); box-shadow: 0 0 4px var(--accent-red); }
  .backend-dot.unknown { background: var(--text-muted); }
  .backend-popover {
    position: absolute; top: 100%; right: 0; margin-top: 8px;
    background: var(--bg-card);
    border: 1px solid var(--border-primary);
    border-radius: var(--radius);
    padding: 16px;
    min-width: 340px;
    box-shadow: 0 12px 40px rgba(0,0,0,0.4);
    z-index: 50;
  }
  .backend-popover h4 {
    font-size: 12px; font-weight: 600; margin-bottom: 10px;
    color: var(--text-primary);
  }
  .backend-url-row {
    display: flex; gap: 8px; align-items: center;
  }
  .backend-url-row input {
    flex: 1;
    background: var(--bg-primary);
    border: 1px solid var(--border-primary);
    border-radius: var(--radius);
    padding: 7px 10px;
    color: var(--text-primary);
    font-family: var(--font-mono);
    font-size: 12px;
  }
  .backend-url-row input:focus { outline: none; border-color: var(--accent-blue); }
  .backend-status-msg {
    font-size: 11px; margin-top: 8px;
    font-family: var(--font-mono);
  }

  /* ── Parsing Indicator ───────── */
  .parsing-banner {
    display: flex; align-items: center; gap: 10px;
    padding: 10px 16px;
    background: #3b82f610;
    border: 1px solid #3b82f630;
    border-radius: var(--radius);
    margin-top: 12px;
    font-size: 13px;
  }
  .parsing-spinner {
    width: 16px; height: 16px;
    border: 2px solid var(--border-primary);
    border-top-color: var(--accent-cyan);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }
  .file-chip .parsed-badge {
    font-size: 9px;
    padding: 1px 6px;
    border-radius: 3px;
    font-family: var(--font-mono);
    font-weight: 600;
  }
  .file-chip .parsed-badge.backend { background: #10b98120; color: var(--accent-green); }
  .file-chip .parsed-badge.fallback { background: #f59e0b20; color: var(--accent-orange); }

  /* ── Evidence Viewer Modal ────── */
  .evidence-modal .modal-content {
    max-width: 960px;
    max-height: 90vh;
  }
  .evidence-table {
    width: 100%;
    border-collapse: collapse;
    font-family: var(--font-mono);
    font-size: 11px;
  }
  .evidence-table th {
    text-align: left;
    padding: 8px 10px;
    background: var(--bg-primary);
    border-bottom: 2px solid var(--border-primary);
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    font-size: 10px;
    font-weight: 600;
    position: sticky;
    top: 0;
    z-index: 1;
  }
  .evidence-table td {
    padding: 8px 10px;
    border-bottom: 1px solid var(--border-primary);
    vertical-align: top;
    color: var(--text-secondary);
  }
  .evidence-table tr:hover td { background: var(--bg-card-hover); }
  .evidence-table tr.severity-row-critical { border-left: 3px solid var(--severity-critical); }
  .evidence-table tr.severity-row-high { border-left: 3px solid var(--severity-high); }
  .evidence-table tr.severity-row-medium { border-left: 3px solid var(--severity-medium); }
  .evidence-record-id {
    color: var(--accent-cyan);
    font-weight: 600;
    white-space: nowrap;
  }
  .evidence-event-id {
    color: var(--accent-orange);
    font-weight: 600;
    white-space: nowrap;
  }
  .evidence-timestamp {
    color: var(--text-muted);
    white-space: nowrap;
    font-size: 10px;
  }
  .evidence-content {
    max-width: 480px;
    word-break: break-all;
    line-height: 1.5;
  }
  .evidence-content mark {
    background: #f59e0b30;
    color: var(--accent-orange);
    padding: 0 2px;
    border-radius: 2px;
  }
  .evidence-expand-btn {
    background: none; border: none;
    color: var(--accent-blue);
    cursor: pointer;
    font-family: var(--font-mono);
    font-size: 10px;
    padding: 2px 4px;
  }
  .evidence-expand-btn:hover { text-decoration: underline; }
  .evidence-fields {
    margin-top: 6px;
    padding: 6px 8px;
    background: var(--bg-tertiary);
    border-radius: 4px;
    font-size: 10px;
  }
  .evidence-fields div {
    padding: 1px 0;
    display: flex; gap: 6px;
  }
  .evidence-fields .field-name { color: var(--accent-purple); min-width: 120px; }
  .evidence-fields .field-value { color: var(--text-secondary); word-break: break-all; }
  .evidence-stats {
    display: flex; gap: 16px; padding: 12px 16px;
    background: var(--bg-primary);
    border-bottom: 1px solid var(--border-primary);
    font-family: var(--font-mono); font-size: 11px;
    color: var(--text-muted);
  }
  .evidence-stats span { color: var(--accent-cyan); font-weight: 600; }
  .evidence-search {
    padding: 8px 16px;
    border-bottom: 1px solid var(--border-primary);
  }
  .evidence-search input {
    width: 100%;
    background: var(--bg-primary);
    border: 1px solid var(--border-primary);
    border-radius: var(--radius);
    padding: 8px 12px;
    color: var(--text-primary);
    font-family: var(--font-mono);
    font-size: 12px;
  }
  .evidence-search input:focus { outline: none; border-color: var(--accent-blue); }

  /* ── Timeline ────────────────── */
  .timeline-container {
    position: relative;
    padding: 16px 0 16px 28px;
    margin: 16px 0 24px;
  }
  .timeline-line {
    position: absolute;
    left: 12px; top: 0; bottom: 0;
    width: 2px;
    background: var(--border-primary);
  }
  .timeline-event {
    position: relative;
    margin-bottom: 4px;
    padding: 8px 14px;
    background: var(--bg-card);
    border: 1px solid var(--border-primary);
    border-radius: var(--radius);
    cursor: pointer;
    transition: all 0.2s;
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .timeline-event:hover { border-color: var(--border-accent); background: var(--bg-card-hover); }
  .timeline-dot {
    position: absolute;
    left: -22px; top: 50%; transform: translateY(-50%);
    width: 10px; height: 10px;
    border-radius: 50%;
    border: 2px solid var(--bg-primary);
    z-index: 1;
  }
  .timeline-time {
    font-family: var(--font-mono);
    font-size: 10px;
    color: var(--text-muted);
    min-width: 140px;
    flex-shrink: 0;
  }
  .timeline-finding-name {
    font-size: 12px;
    font-weight: 500;
    flex: 1;
    min-width: 0;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .timeline-event-id {
    font-family: var(--font-mono);
    font-size: 10px;
    color: var(--accent-orange);
    flex-shrink: 0;
  }
  .timeline-record-id {
    font-family: var(--font-mono);
    font-size: 10px;
    color: var(--accent-cyan);
    flex-shrink: 0;
  }
  .timeline-group-header {
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-muted);
    padding: 12px 0 6px;
    font-family: var(--font-mono);
  }

  /* ── IOC Panel ────────────────── */
  .ioc-panel {
    background: var(--bg-card);
    border: 1px solid var(--border-primary);
    border-radius: var(--radius-lg);
    margin-top: 10px;
    margin-bottom: 16px;
    overflow: hidden;
  }
  .ioc-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 12px 16px;
    cursor: pointer;
    transition: background 0.2s;
  }
  .ioc-header:hover { background: var(--bg-card-hover); }
  .ioc-header-left { display: flex; align-items: center; gap: 10px; }
  .ioc-count {
    font-family: var(--font-mono); font-size: 12px; font-weight: 600;
    background: var(--accent-orange); color: white;
    padding: 2px 8px; border-radius: 10px; min-width: 24px; text-align: center;
  }
  .ioc-body { border-top: 1px solid var(--border-primary); padding: 16px; }
  .ioc-input-row { display: flex; gap: 8px; margin-bottom: 12px; }
  .ioc-input-row input {
    flex: 1; background: var(--bg-primary);
    border: 1px solid var(--border-primary); border-radius: var(--radius);
    padding: 8px 12px; color: var(--text-primary);
    font-family: var(--font-mono); font-size: 12px;
  }
  .ioc-input-row input:focus { outline: none; border-color: var(--accent-blue); }
  .ioc-tags { display: flex; flex-wrap: wrap; gap: 6px; max-height: 200px; overflow-y: auto; }
  .ioc-tag {
    display: inline-flex; align-items: center; gap: 6px;
    padding: 4px 10px; border-radius: 4px;
    font-family: var(--font-mono); font-size: 11px;
  }
  .ioc-tag.ip { background: #ef444415; border: 1px solid #ef444430; color: var(--accent-red); }
  .ioc-tag.domain { background: #f59e0b15; border: 1px solid #f59e0b30; color: var(--accent-orange); }
  .ioc-tag button {
    background: none; border: none; cursor: pointer;
    color: inherit; opacity: 0.6; font-size: 13px; padding: 0; display: flex;
  }
  .ioc-tag button:hover { opacity: 1; }
  .ioc-toggle {
    position: relative; width: 36px; height: 20px;
    background: var(--bg-tertiary); border: 1px solid var(--border-primary);
    border-radius: 10px; cursor: pointer; transition: all 0.2s;
    flex-shrink: 0;
  }
  .ioc-toggle.active { background: var(--accent-blue); border-color: var(--accent-blue); }
  .ioc-toggle::after {
    content: ''; position: absolute;
    width: 14px; height: 14px; border-radius: 50%;
    background: white; top: 2px; left: 2px;
    transition: transform 0.2s;
  }
  .ioc-toggle.active::after { transform: translateX(16px); }

  /* ── Case Management ──────────── */
  .case-btn {
    font-size: 11px !important;
    padding: 6px 12px !important;
    height: 32px;
    line-height: 1;
    display: inline-flex !important;
    align-items: center;
    box-sizing: border-box;
    white-space: nowrap;
  }
  .case-banner {
    display: flex; align-items: center; justify-content: space-between;
    padding: 10px 16px;
    background: var(--bg-card);
    border: 1px solid var(--border-primary);
    border-radius: var(--radius);
    margin-bottom: 16px;
  }
  .case-banner-left { display: flex; align-items: center; gap: 12px; }
  .case-name {
    font-weight: 700; font-size: 14px;
    color: var(--accent-cyan);
    font-family: var(--font-display);
  }
  .case-meta-item {
    font-family: var(--font-mono);
    font-size: 10px;
    color: var(--text-muted);
  }
  .case-actions { display: flex; gap: 6px; }

  .timeline-pagination {
    display: flex; align-items: center; justify-content: center;
    gap: 6px; padding: 16px 0;
    flex-wrap: wrap;
  }
  .timeline-pagination button {
    font-family: var(--font-mono);
    font-size: 11px;
    padding: 5px 10px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border-primary);
    border-radius: 4px;
    color: var(--text-secondary);
    cursor: pointer;
    transition: all 0.2s;
    min-width: 32px;
  }
  .timeline-pagination button:hover { border-color: var(--text-muted); color: var(--text-primary); }
  .timeline-pagination button.active {
    background: var(--accent-blue);
    border-color: var(--accent-blue);
    color: white;
  }
  .timeline-pagination button:disabled { opacity: 0.3; cursor: not-allowed; }
  .timeline-pagination .page-info {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--text-muted);
    padding: 0 8px;
  }

  /* ── Rule Editor Modal ────────── */
  .modal-overlay {
    position: fixed; inset: 0;
    background: rgba(10,14,23,0.88);
    display: flex; align-items: center; justify-content: center;
    z-index: 200;
    backdrop-filter: blur(6px);
    padding: 20px;
  }
  .modal-content {
    background: var(--bg-secondary);
    border: 1px solid var(--border-primary);
    border-radius: var(--radius-lg);
    width: 100%;
    max-width: 720px;
    max-height: 85vh;
    overflow-y: auto;
    box-shadow: 0 25px 60px rgba(0,0,0,0.5);
  }
  .modal-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 20px 24px;
    border-bottom: 1px solid var(--border-primary);
    position: sticky; top: 0; background: var(--bg-secondary); z-index: 1;
  }
  .modal-header h3 { font-size: 16px; font-weight: 700; }
  .modal-close {
    background: none; border: none; color: var(--text-muted);
    cursor: pointer; font-size: 20px; padding: 4px 8px;
    border-radius: 4px; transition: all 0.2s;
  }
  .modal-close:hover { color: var(--text-primary); background: var(--bg-tertiary); }
  .modal-body { padding: 24px; }
  .modal-footer {
    display: flex; align-items: center; justify-content: space-between;
    padding: 16px 24px;
    border-top: 1px solid var(--border-primary);
    position: sticky; bottom: 0; background: var(--bg-secondary);
  }
  .form-group { margin-bottom: 16px; }
  .form-label {
    display: block;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: var(--text-muted);
    margin-bottom: 6px;
    font-family: var(--font-mono);
  }
  .form-input, .form-select, .form-textarea {
    width: 100%;
    background: var(--bg-primary);
    border: 1px solid var(--border-primary);
    border-radius: var(--radius);
    padding: 10px 12px;
    color: var(--text-primary);
    font-family: var(--font-mono);
    font-size: 13px;
    transition: border-color 0.2s;
  }
  .form-input:focus, .form-select:focus, .form-textarea:focus {
    outline: none; border-color: var(--accent-blue);
  }
  .form-select { cursor: pointer; appearance: none; }
  .form-textarea { min-height: 80px; resize: vertical; }
  .form-hint {
    font-size: 11px; color: var(--text-muted);
    margin-top: 4px; font-family: var(--font-mono);
  }
  .form-row {
    display: grid; grid-template-columns: 1fr 1fr; gap: 12px;
  }
  @media (max-width: 600px) { .form-row { grid-template-columns: 1fr; } }
  .tag-input-container {
    display: flex; flex-wrap: wrap; gap: 6px;
    background: var(--bg-primary);
    border: 1px solid var(--border-primary);
    border-radius: var(--radius);
    padding: 8px;
    min-height: 42px;
    cursor: text;
  }
  .tag-input-container:focus-within { border-color: var(--accent-blue); }
  .tag-item {
    display: inline-flex; align-items: center; gap: 4px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border-primary);
    border-radius: 4px;
    padding: 2px 8px;
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--text-secondary);
  }
  .tag-item button {
    background: none; border: none; color: var(--text-muted);
    cursor: pointer; padding: 0; font-size: 14px; line-height: 1;
    display: flex;
  }
  .tag-item button:hover { color: var(--accent-red); }
  .tag-input {
    flex: 1; min-width: 100px;
    background: none; border: none;
    color: var(--text-primary);
    font-family: var(--font-mono);
    font-size: 12px;
    outline: none;
  }
  .tag-input::placeholder { color: var(--text-muted); }
  .rule-actions-bar {
    display: flex; gap: 8px; align-items: center; justify-content: space-between;
    margin-bottom: 16px;
  }
  .rule-action-btn-edit, .rule-action-btn-del {
    background: none; border: none; cursor: pointer;
    padding: 4px 8px; border-radius: 4px; transition: all 0.2s;
    font-size: 12px; font-family: var(--font-mono);
    display: inline-flex; align-items: center; gap: 4px;
  }
  .rule-action-btn-edit { color: var(--accent-blue); }
  .rule-action-btn-edit:hover { background: #3b82f615; }
  .rule-action-btn-del { color: var(--accent-red); }
  .rule-action-btn-del:hover { background: #ef444415; }
  .regex-valid { border-color: var(--accent-green) !important; }
  .regex-invalid { border-color: var(--accent-red) !important; }
  .regex-status {
    font-size: 11px; margin-top: 4px;
    font-family: var(--font-mono);
  }
  .regex-status.valid { color: var(--accent-green); }
  .regex-status.invalid { color: var(--accent-red); }

  /* ── Scrollbar ────────────────── */
  ::-webkit-scrollbar { width: 6px; }
  ::-webkit-scrollbar-track { background: var(--bg-primary); }
  ::-webkit-scrollbar-thumb { background: var(--border-primary); border-radius: 3px; }
  ::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }

  /* ── Log Type Legend ──────────── */
  .log-color-win { background: var(--accent-blue); }
  .log-color-web { background: var(--accent-cyan); }
  .log-color-reg { background: var(--accent-purple); }

  .filter-bar {
    display: flex; gap: 8px; align-items: center; flex-wrap: wrap;
  }
  .filter-chip {
    font-size: 11px; padding: 4px 10px;
    border-radius: 20px; cursor: pointer;
    border: 1px solid var(--border-primary);
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    font-family: var(--font-mono);
    transition: all 0.2s;
  }
  .filter-chip.active { border-color: var(--accent-blue); color: var(--accent-blue); background: #3b82f610; }
  .filter-chip:hover { border-color: var(--text-muted); }

  /* ── Tab bar ──────────────────── */
  .tab-bar { display: flex; gap: 2px; margin-bottom: 20px; background: var(--bg-secondary); border-radius: var(--radius); padding: 3px; }
  .tab-btn {
    flex: 1; padding: 10px 16px;
    background: transparent; border: none;
    color: var(--text-muted); cursor: pointer;
    font-family: var(--font-display); font-size: 13px; font-weight: 500;
    border-radius: 6px; transition: all 0.2s;
  }
  .tab-btn.active { background: var(--bg-tertiary); color: var(--text-primary); }
  .tab-btn:hover:not(.active) { color: var(--text-secondary); }

  .rule-browser {
    background: var(--bg-card);
    border: 1px solid var(--border-primary);
    border-radius: var(--radius-lg);
    overflow: hidden;
  }
  .rule-item {
    padding: 14px 20px;
    border-bottom: 1px solid var(--border-primary);
    display: flex; align-items: center; justify-content: space-between;
    cursor: pointer;
    transition: background 0.2s;
  }
  .rule-item:last-child { border-bottom: none; }
  .rule-item:hover { background: var(--bg-card-hover); }
  .rule-item-left { display: flex; align-items: center; gap: 12px; }
  .rule-id { font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); min-width: 64px; }
  .rule-name { font-size: 13px; font-weight: 500; }
  .rule-item-right { display: flex; align-items: center; gap: 8px; }
`;

// ─── MAIN APPLICATION COMPONENT ─────────────────────────────────────────────
export default function SigilDFIR() {
  const [artifacts, setArtifacts] = useState([]);
  const [findings, setFindings] = useState([]);
  const [overallScore, setOverallScore] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [expandedFindings, setExpandedFindings] = useState(new Set());
  const [bookmarkedEvents, setBookmarkedEvents] = useState(new Set()); // Set of "findingId:recordId" keys
  const [showPaste, setShowPaste] = useState(false);
  const [filesExpanded, setFilesExpanded] = useState(false);
  const [pasteContent, setPasteContent] = useState("");
  const [dragover, setDragover] = useState(false);
  const [activeTab, setActiveTab] = useState("analyze");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [ruleExpanded, setRuleExpanded] = useState(null);
  const [customRules, setCustomRules] = useState({ windows_event_log: [], web_server_log: [], registry: [] });
  const [editingRule, setEditingRule] = useState(null);
  const [showRuleEditor, setShowRuleEditor] = useState(false);
  const [parsingFiles, setParsingFiles] = useState(0);
  const [backendUrl, setBackendUrl] = useState(
    (typeof window !== "undefined" && window.sigil?.backendUrl) || "http://127.0.0.1:8001"
  );
  const [showBackendConfig, setShowBackendConfig] = useState(false);
  const [showReportMenu, setShowReportMenu] = useState(false);
  const [lateralMovement, setLateralMovement] = useState(null); // { data, loading, error }
  const [lmTab, setLmTab] = useState("graph"); // graph | timeline | chains | findings
  const [lmPhase, setLmPhase] = useState("config"); // config | results
  const [lmSelectedNode, setLmSelectedNode] = useState(null);
  const [lmNodePositions, setLmNodePositions] = useState({});
  const [lmSelectedEids, setLmSelectedEids] = useState(new Set([
    "4624", "4625", "4634", "4647", "4648",  // Logon
    "4672",                                     // Privilege
    "4768", "4769", "4776",                     // Kerberos
    "7045", "4697",                             // Service
    "4698",                                     // Sched Task
    "5140", "5145",                             // SMB
    "4688",                                     // Process
    "4104",                                     // PowerShell
    "5861",                                     // WMI
    "4778", "4779", "1149", "21", "22", "23", "24", "25", "39", "40",  // RDP
  ]));
  const lmDragRef = useRef(null);
  const lmSvgRef = useRef(null);
  const [backendStatus, setBackendStatus] = useState(null);
  const [evidenceViewer, setEvidenceViewer] = useState(null);
  const [processTree, setProcessTree] = useState(null); // { loading, data, error }
  const [ptExpandedNodes, setPtExpandedNodes] = useState(new Set());
  const [ptSevFilter, setPtSevFilter] = useState("all");
  const [ptSearch, setPtSearch] = useState("");
  const [caseMeta, setCaseMeta] = useState({ name: "", examiner: "", description: "", createdAt: null });
  const [caseActive, setCaseActive] = useState(false); // true when a case is open with SQLite backend
  const [caseDir, setCaseDir] = useState("");
  const [caseLoading, setCaseLoading] = useState(false);
  const [caseScreen, setCaseScreen] = useState("gate"); // gate | create
  const [newCaseName, setNewCaseName] = useState("");
  const [newCaseExaminer, setNewCaseExaminer] = useState("");
  const [newCaseOrg, setNewCaseOrg] = useState("");
  const [newCaseDesc, setNewCaseDesc] = useState("");
  const [newCasePath, setNewCasePath] = useState("");
  const [showCaseModal, setShowCaseModal] = useState(false);
  const [caseModalMode, setCaseModalMode] = useState("create"); // "create" | "save"
  // ── Case recovery: check if backend has an active case on mount ──
  useEffect(() => {
    fetch(`${backendUrl}/case/info`).then(r => r.json()).then(data => {
      if (data.status === "active" && data.metadata) {
        setCaseMeta({
          name: data.metadata.case_name || "",
          examiner: data.metadata.examiner || "",
          description: data.metadata.description || "",
          createdAt: data.metadata.created_at || null,
        });
        setCaseDir(data.case_dir || "");
        setCaseActive(true);
        if (data.artifacts) {
          setArtifacts(data.artifacts.map(a => ({
            name: a.filename, logType: a.log_type, format: a.format,
            eventCount: a.event_count, id: a.id, sha256: a.sha256,
            hashes: { md5: a.md5, sha1: a.sha1, sha256: a.sha256, file_size: a.file_size },
            parsed: true, backendParsed: true,
          })));
        }
        if (data.findings && data.findings.length > 0) {
          setFindings(data.findings.map((f, idx) => ({
            id: f.rule_id, dbId: f.id, uid: `${f.rule_id}_${f.id || idx}`, name: f.rule_name,
            description: f.description, severity: f.severity,
            mitre: f.mitre || [], matchCount: f.match_count,
            keywordHits: f.keyword_hits, confidence: f.confidence,
            nextSteps: f.next_steps || [], isIocRule: f.is_ioc_rule,
            matchedEvents: (f.matched_events || []).map(e => ({
              timestamp: e.timestamp, eventId: e.event_id, recordId: e.record_id,
              content: e.content, message: e.message, fields: e.fields || {},
              eventDataXml: e.event_data_xml || "", context: e.context || [],
            })),
          })));
        }
        if (data.overall_score) setOverallScore(data.overall_score);
        if (data.bookmarks) setBookmarkedEvents(new Set(data.bookmarks));
        if (data.lm_results) {
          setLateralMovement({ loading: false, data: data.lm_results, error: null });
          setLmPhase("results");
          // Initialize node positions
          const nodes = data.lm_results?.graph?.nodes || [];
          const positions = {};
          const cx = 450, cy = 250, radius = Math.min(200, Math.max(80, nodes.length * 12));
          nodes.forEach((n, i) => {
            const angle = (2 * Math.PI * i) / nodes.length;
            positions[n.id] = { x: cx + radius * Math.cos(angle), y: cy + radius * Math.sin(angle) };
          });
          setLmNodePositions(positions);
        }
        console.log("[SIGIL] Case recovered from backend:", data.metadata.case_name);
      }
    }).catch(() => {});
  }, []);

  const [iocList, setIocList] = useState([]); // [{ value, type: "ip"|"domain" }]
  const [iocEnabled, setIocEnabled] = useState(true);
  const [showIocPanel, setShowIocPanel] = useState(false);
  const [iocInput, setIocInput] = useState("");
  const caseImportRef = useRef(null);
  const iocFileRef = useRef(null);
  const fileInputRef = useRef(null);

  // Parse EVTX via backend API
  // ── File Upload via Backend /case/upload ─────────────────────────────
  const parseViaBackend = useCallback(async (file) => {
    setParsingFiles(prev => prev + 1);
    try {
      const formData = new FormData();
      formData.append("file", file);
      const res = await fetch(`${backendUrl}/case/upload`, { method: "POST", body: formData });
      const data = await res.json();
      if (data.status === "success") {
        setArtifacts(prev => [...prev, {
          name: file.name,
          size: file.size,
          file,
          content: "",
          logType: data.log_type || "unknown",
          timestamp: Date.now(),
          parsedBackend: true,
          eventCount: data.event_count,
          events: null,
          webLogFormat: data.format || "Unknown",
          hashes: data.hashes || null,
          id: data.artifact?.id,
          sha256: data.artifact?.sha256,
        }]);
        setBackendStatus("ok");
      } else if (data.status === "duplicate") {
        console.log(`[SIGIL] Skipped duplicate: ${file.name}`);
      } else {
        throw new Error(data.message || "Backend returned error");
      }
    } catch (err) {
      console.error("Backend parse failed:", err);
      setBackendStatus("error");
      // Minimal fallback: store raw file for later /analyze call
      const reader = new FileReader();
      reader.onload = (e) => {
        const content = e.target.result;
        setArtifacts(prev => [...prev, {
          name: file.name, size: file.size, file, content,
          logType: "unknown", timestamp: Date.now(),
          parsedBackend: false
        }]);
      };
      reader.readAsText(file);
    } finally {
      setParsingFiles(prev => prev - 1);
    }
  }, [backendUrl]);

  const handleFileRead = useCallback((file) => {
    parseViaBackend(file);
  }, [parseViaBackend]);

  const handleFiles = useCallback((files) => {
    Array.from(files).forEach(handleFileRead);
  }, [handleFileRead]);

  // Backend health check
  const checkBackend = useCallback(async () => {
    try {
      const res = await fetch(`${backendUrl}/health`);
      if (res.ok) {
        const data = await res.json();
        setBackendStatus(data.status === "ok" ? "ok" : "error");
      } else {
        setBackendStatus("error");
      }
    } catch {
      setBackendStatus("error");
    }
  }, [backendUrl]);

  const handleDrop = useCallback((e) => {
    e.preventDefault(); setDragover(false);
    handleFiles(e.dataTransfer.files);
  }, [handleFiles]);

  const handlePasteSubmit = useCallback(() => {
    if (!pasteContent.trim()) return;
    // Create a Blob/File from pasted content and send to backend
    const blob = new Blob([pasteContent], { type: "text/plain" });
    const file = new File([blob], `pasted_log_${Date.now()}.txt`, { type: "text/plain" });
    parseViaBackend(file);
    setPasteContent("");
    setShowPaste(false);
  }, [pasteContent, parseViaBackend]);

  const removeArtifact = useCallback((idx) => {
    setArtifacts(prev => prev.filter((_, i) => i !== idx));
  }, []);

  // ── Case Management Functions ──
  const createCase = useCallback(async () => {
    if (!newCaseName.trim() || !newCaseExaminer.trim() || !newCasePath.trim()) {
      alert("Case Name, Examiner, and Save Location are required.");
      return;
    }
    setCaseLoading(true);
    try {
      const res = await fetch(`${backendUrl}/case/create`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          case_name: newCaseName.trim(),
          examiner: newCaseExaminer.trim(),
          organization: newCaseOrg.trim(),
          description: newCaseDesc.trim(),
          save_path: newCasePath.trim(),
        }),
      });
      const data = await res.json();
      if (data.status === "success") {
        setCaseMeta({
          name: newCaseName.trim(), examiner: newCaseExaminer.trim(),
          description: newCaseDesc.trim(), createdAt: data.metadata?.created_at,
        });
        setCaseDir(data.case_dir || "");
        setCaseActive(true);
        setArtifacts([]); setFindings([]); setOverallScore(null);
        setBookmarkedEvents(new Set()); setLateralMovement(null); setLmPhase("config");
      } else {
        alert(`Failed to create case: ${data.message}`);
      }
    } catch (err) {
      alert(`Error creating case: ${err.message}`);
    }
    setCaseLoading(false);
  }, [backendUrl, newCaseName, newCaseExaminer, newCaseOrg, newCaseDesc, newCasePath]);

  const openCaseFromDisk = useCallback(async () => {
    setCaseLoading(true);
    try {
      const browseRes = await fetch(`${backendUrl}/case/browse-file`, { method: "POST" });
      const browseData = await browseRes.json();
      if (browseData.status !== "success") { setCaseLoading(false); return; }

      const formData = new FormData();
      const res = await fetch(`${backendUrl}/case/open`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: `case_path=${encodeURIComponent(browseData.path)}`,
      });
      const data = await res.json();
      if (data.status === "success") {
        setCaseMeta({
          name: data.metadata?.case_name || "", examiner: data.metadata?.examiner || "",
          description: data.metadata?.description || "", createdAt: data.metadata?.created_at,
        });
        setCaseDir(data.case_dir || "");
        setCaseActive(true);
        // Restore artifacts
        if (data.artifacts) {
          setArtifacts(data.artifacts.map(a => ({
            name: a.filename, logType: a.log_type, format: a.format,
            eventCount: a.event_count, id: a.id, sha256: a.sha256,
            hashes: { md5: a.md5, sha1: a.sha1, sha256: a.sha256, file_size: a.file_size },
            parsed: true, backendParsed: true,
          })));
        }
        // Restore findings
        if (data.findings && data.findings.length > 0) {
          setFindings(data.findings.map((f, idx) => ({
            id: f.rule_id, dbId: f.id, uid: `${f.rule_id}_${f.id || idx}`, name: f.rule_name,
            description: f.description, severity: f.severity,
            mitre: f.mitre || [], matchCount: f.match_count,
            keywordHits: f.keyword_hits, confidence: f.confidence,
            nextSteps: f.next_steps || [], isIocRule: f.is_ioc_rule,
            matchedEvents: (f.matched_events || []).map(e => ({
              timestamp: e.timestamp, eventId: e.event_id, recordId: e.record_id,
              content: e.content, message: e.message, fields: e.fields || {},
              eventDataXml: e.event_data_xml || "", context: e.context || [],
            })),
          })));
        }
        if (data.overall_score) setOverallScore(data.overall_score);
        if (data.bookmarks) setBookmarkedEvents(new Set(data.bookmarks));
        if (data.lm_results) {
          setLateralMovement({ loading: false, data: data.lm_results, error: null });
          setLmPhase("results");
          // Initialize node positions for restored LM graph
          const nodes = data.lm_results?.graph?.nodes || [];
          const positions = {};
          const cx = 450, cy = 250, radius = Math.min(200, Math.max(80, nodes.length * 12));
          nodes.forEach((n, i) => {
            const angle = (2 * Math.PI * i) / nodes.length;
            positions[n.id] = { x: cx + radius * Math.cos(angle), y: cy + radius * Math.sin(angle) };
          });
          setLmNodePositions(positions);
        }
      } else {
        alert(`Failed to open case: ${data.message}`);
      }
    } catch (err) {
      alert(`Error opening case: ${err.message}`);
    }
    setCaseLoading(false);
  }, [backendUrl]);

  const closeCase = useCallback(async () => {
    try {
      await fetch(`${backendUrl}/case/close`, { method: "POST" });
    } catch {}
    setCaseActive(false); setCaseDir(""); setCaseMeta({ name: "", examiner: "", description: "", createdAt: null });
    setArtifacts([]); setFindings([]); setOverallScore(null); setBookmarkedEvents(new Set());
    setLateralMovement(null); setLmPhase("config"); setLmSelectedNode(null); setLmNodePositions({});
    setProcessTree(null); setActiveTab("analyze"); setCaseScreen("gate");
  }, [backendUrl]);

  const browseCaseFolder = useCallback(async () => {
    try {
      const res = await fetch(`${backendUrl}/case/browse-folder`, { method: "POST" });
      const data = await res.json();
      if (data.status === "success") setNewCasePath(data.path);
    } catch {}
  }, [backendUrl]);

  const runProcessTree = useCallback(async () => {
    setProcessTree({ loading: true, data: null, error: null });
    try {
      const res = await fetch(`${backendUrl}/case/process-tree`, { method: "POST" });
      const data = await res.json();
      if (data.status === "success") {
        setProcessTree({ loading: false, data, error: null });
        // Auto-expand nodes with detections
        const expanded = new Set();
        (data.tree || []).forEach(n => {
          if (n.has_detection) expanded.add(n.key);
        });
        setPtExpandedNodes(expanded);
      } else if (data.status === "no_data") {
        setProcessTree({ loading: false, data: { tree: [], findings: [], summary: { total_processes: 0, total_findings: 0, critical_count: 0, high_count: 0, medium_count: 0 } }, error: null });
      } else {
        setProcessTree({ loading: false, data: null, error: data.message || "Analysis failed" });
      }
    } catch (err) {
      setProcessTree({ loading: false, data: null, error: err.message });
    }
  }, [backendUrl]);

  const openLateralMovement = useCallback(() => {
    const evtxArtifacts = artifacts.filter(a => a.logType === "windows_event_log" && a.file);
    if (evtxArtifacts.length === 0) {
      alert("No EVTX artifacts loaded.");
      return;
    }
    setLmPhase("config");
    setLmSelectedNode(null);
    setLmNodePositions({});
    setLateralMovement({ loading: false, data: null, error: null });
  }, [artifacts]);

  const runLateralMovement = useCallback(async () => {
    setLateralMovement({ loading: true, data: null, error: null });
    setLmPhase("results");
    setLmTab("graph");
    setLmSelectedNode(null);
    try {
      const res = await fetch(`${backendUrl}/case/lateral-movement`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_eids: [...lmSelectedEids] }),
      });
      const data = await res.json();

      if (data.status === "success") {
        const nodes = data.graph?.nodes || [];
        const positions = {};
        const cx = 450, cy = 250, radius = Math.min(200, Math.max(80, nodes.length * 12));
        nodes.forEach((n, i) => {
          const angle = (2 * Math.PI * i) / nodes.length;
          positions[n.id] = { x: cx + radius * Math.cos(angle), y: cy + radius * Math.sin(angle) };
        });
        setLmNodePositions(positions);

        setLateralMovement({
          loading: false, error: null,
          data: {
            logons: data.logons || [],
            graph: data.graph || { nodes: [], edges: [] },
            chains: data.chains || [],
            findings: data.findings || [],
            summary: data.summary || {},
          }
        });
      } else {
        setLateralMovement({ loading: false, data: null, error: data.message || "Analysis failed" });
      }
    } catch (err) {
      setLateralMovement({ loading: false, data: null, error: err.message });
    }
  }, [backendUrl, lmSelectedEids]);

  const generateReport = useCallback(async (mode = "all") => {
    try {
      let reportFindings = findings;
      let reportLabel = "Full Report";
      if (mode === "bookmarked") {
        // Filter findings to only include bookmarked events
        reportFindings = findings.map(f => {
          const bookmarkedEvts = (f.matchedEvents || []).filter(e => {
            const rid = e.recordId || e.record_id || "";
            return bookmarkedEvents.has(`${f.uid || f.id}:${rid}`);
          });
          if (bookmarkedEvts.length === 0) return null;
          return { ...f, matchedEvents: bookmarkedEvts, matchCount: bookmarkedEvts.length };
        }).filter(Boolean);
        reportLabel = `Bookmarked Evidence (${totalBookmarkedEvents} events)`;
        if (reportFindings.length === 0) {
          alert("No bookmarked events. Click the ☆ star on individual events in the Evidence Viewer to bookmark them.");
          return;
        }
      } else if (mode === "critical-high") {
        reportFindings = findings.filter(f => f.severity === "critical" || f.severity === "high");
        reportLabel = "Critical & High Findings";
      } else if (mode === "critical") {
        reportFindings = findings.filter(f => f.severity === "critical");
        reportLabel = "Critical Findings Only";
      }

      const isBookmarkedReport = mode === "bookmarked";
      const payload = {
        case_meta: { ...caseMeta, report_scope: reportLabel },
        is_bookmarked_report: isBookmarkedReport,
        findings: reportFindings.map(f => ({
          id: f.id,
          name: f.name,
          description: f.description || "",
          severity: f.severity,
          confidence: f.confidence || 0,
          mitre: f.mitre || [],
          match_count: f.matchCount || 0,
          keyword_hits: f.keywordHits || 0,
          next_steps: f.nextSteps || [],
          is_ioc_rule: f.isIocRule || false,
          is_bookmarked: isBookmarkedReport,
          matched_events: (isBookmarkedReport
            ? (f.matchedEvents || [])
            : (f.matchedEvents || []).slice(0, 10)
          ).map(e => ({
            record_id: e.recordId || e.record_id || "",
            event_id: e.eventId || e.event_id || "",
            timestamp: e.timestamp || "",
            content: (e.content || e.message || "").slice(0, 1000),
            context: e.context || [],
            fields: e.structuredFields || e.fields || null,
          })),
        })),
        overall_score: overallScore,
        artifacts: artifacts.map(a => ({
          name: a.name, log_type: a.logType, event_count: a.eventCount || 0,
          hashes: a.hashes || null
        })),
        ioc_list: iocList,
      };

      const res = await fetch(`${backendUrl}/case/report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Report generation failed");
      }

      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      const safeName = (caseMeta.name || "sigil_report").replace(/[^a-zA-Z0-9_-]/g, "_").toLowerCase();
      a.download = `${safeName}_report.docx`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      alert("Report generation failed: " + err.message);
      console.error("Report error:", err);
    }
  }, [findings, overallScore, artifacts, caseMeta, iocList, backendUrl, bookmarkedEvents]);

  const runAnalysis = useCallback(async () => {
    setScanning(true);
    setFindings([]);
    setOverallScore(null);
    setExpandedFindings(new Set());
    setTimelinePage(0);
    setTimelineSevFilter("all");

    const iocPayload = iocEnabled && iocList.length > 0 ? JSON.stringify(iocList) : null;
    let allFindings = [];

    try {
      const formData = new FormData();
      if (iocPayload) formData.append("ioc_list", iocPayload);
      formData.append("ioc_enabled", String(iocEnabled));
      const res = await fetch(`${backendUrl}/case/analyze`, { method: "POST", body: formData });
      const data = await res.json();

      if (data.status === "success" && data.findings) {
        allFindings = data.findings.map((f, idx) => ({
          id: f.rule_id || f.id,
          dbId: f.id,
          uid: `${f.rule_id || f.id}_${f.id || idx}`,
          name: f.rule_name || f.name,
          description: f.description,
          severity: f.severity,
          mitre: f.mitre || [],
          matchCount: f.match_count,
          keywordHits: f.keyword_hits,
          confidence: f.confidence,
          excerpts: [],
          matchedEvents: (f.matched_events || []).map(e => ({
            timestamp: e.timestamp,
            eventId: e.event_id,
            recordId: e.record_id || String(e.id),
            content: e.content,
            message: e.message,
            structuredFields: e.fields,
            line_index: e.line_index,
            context: e.context || [],
            eventDataXml: e.event_data_xml || ""
          })),
          nextSteps: f.next_steps || [],
          isIocRule: f.is_ioc_rule || false,
        }));
        if (data.overall_score) setOverallScore(data.overall_score);
      }
    } catch (err) {
      console.error("Analysis failed:", err);
    }

    setFindings(allFindings);
    setScanning(false);
    if (allFindings.length > 0) setExpandedFindings(new Set([allFindings[0].uid || allFindings[0].id]));
  }, [artifacts, iocEnabled, iocList, backendUrl]);

  const toggleFinding = (id) => {
    setExpandedFindings(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const toggleEventBookmark = (findingId, recordId) => {
    const scrollPos = evScrollRef.current?.scrollTop || 0;
    const key = `${findingId}:${recordId}`;
    setBookmarkedEvents(prev => {
      const next = new Set(prev);
      next.has(key) ? next.delete(key) : next.add(key);
      return next;
    });
    // Restore scroll after re-render
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        if (evScrollRef.current) evScrollRef.current.scrollTop = scrollPos;
      });
    });
  };

  const getBookmarkedCountForFinding = (findingId) => {
    let count = 0;
    for (const key of bookmarkedEvents) {
      if (key.startsWith(findingId + ":")) count++;
    }
    return count;
  };

  const totalBookmarkedEvents = bookmarkedEvents.size;

  const filteredFindings = severityFilter === "all" ? findings : findings.filter(f => f.severity === severityFilter);

  const getConfidenceColor = (c) => {
    if (c >= 70) return "var(--accent-red)";
    if (c >= 45) return "var(--accent-orange)";
    return "var(--accent-blue)";
  };

  const logTypeLabel = (t) => ({ windows_event_log: "Windows Events", web_server_log: "Web Server", registry: "Registry" }[t] || "Unknown");
  const logTypeColor = (t) => ({ windows_event_log: "var(--accent-blue)", web_server_log: "var(--accent-cyan)", registry: "var(--accent-purple)" }[t] || "var(--text-muted)");

  const exportJSON = () => {
    const report = {
      tool: "SIGIL DFIR Compromise Assessment Tool",
      version: "1.0.0",
      timestamp: new Date().toISOString(),
      case: hasActiveCase ? caseMeta : null,
      overallAssessment: overallScore,
      artifactsAnalyzed: artifacts.map(a => ({ name: a.name, type: a.logType, size: a.size })),
      findings: findings.map(f => ({
        id: f.id, name: f.name, severity: f.severity,
        confidence: f.confidence, description: f.description,
        mitreTechniques: f.mitre.map(m => MITRE_TECHNIQUES[m]).filter(Boolean),
        matchCount: f.matchCount, keywordHits: f.keywordHits,
        matchedEventCount: (f.matchedEvents || []).length,
        nextSteps: f.nextSteps, source: f.source
      }))
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url;
    const prefix = hasActiveCase ? caseMeta.name.replace(/[^a-zA-Z0-9]/g, "_").toLowerCase() : "sigil_report";
    a.download = `${prefix}_${new Date().toISOString().slice(0,10)}.json`;
    a.click(); URL.revokeObjectURL(url);
  };

  const exportMarkdown = () => {
    let md = `# SIGIL DFIR Assessment Report\n\n`;
    if (hasActiveCase) {
      md += `**Case:** ${caseMeta.name}\n\n`;
      if (caseMeta.examiner) md += `**Examiner:** ${caseMeta.examiner}\n\n`;
      if (caseMeta.description) md += `**Description:** ${caseMeta.description}\n\n`;
    }
    md += `**Date:** ${new Date().toISOString()}\n\n`;
    md += `**Overall Assessment:** ${overallScore?.label || "N/A"} (Score: ${overallScore?.score || 0})\n\n`;
    md += `## Artifacts Analyzed\n\n`;
    artifacts.forEach(a => { md += `- **${a.name}** — ${logTypeLabel(a.logType)} (${((a.size || a.hashes?.file_size || 0)/1024).toFixed(1)} KB)\n`; });
    md += `\n## Findings (${findings.length})\n\n`;
    findings.forEach(f => {
      md += `### [${f.severity.toUpperCase()}] ${f.name} (${f.id})\n\n`;
      md += `- **Confidence:** ${f.confidence}%\n`;
      md += `- **MITRE ATT&CK:** ${f.mitre.join(", ")}\n`;
      md += `- **Source:** ${f.source}\n`;
      md += `- **Matches:** ${f.matchCount} pattern | ${f.keywordHits} keyword | ${(f.matchedEvents || []).length} events\n\n`;
      md += `${f.description}\n\n`;
      md += `**Next Steps:**\n`;
      f.nextSteps.forEach(s => { md += `1. ${s}\n`; });
      md += `\n---\n\n`;
    });
    const blob = new Blob([md], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url;
    const prefix = hasActiveCase ? caseMeta.name.replace(/[^a-zA-Z0-9]/g, "_").toLowerCase() : "sigil_report";
    a.download = `${prefix}_${new Date().toISOString().slice(0,10)}.md`;
    a.click(); URL.revokeObjectURL(url);
  };

  // All rules flat for the browser
  const allRules = [
    ...((customRules.windows_event_log || []).map(r => ({ ...r, logType: "windows_event_log" }))),
    ...((customRules.web_server_log || []).map(r => ({ ...r, logType: "web_server_log" }))),
    ...((customRules.registry || []).map(r => ({ ...r, logType: "registry" }))),
  ];

  // ── Rule Editor Helpers ──────────────────────────────────────────────────
  const makeEmptyRule = (logType = "windows_event_log") => ({
    id: "",
    name: "",
    description: "",
    severity: "medium",
    mitre: [],
    pattern: "",
    altPatterns: "",
    keywords: [],
    nextSteps: [""],
    logType
  });

  const ruleToForm = (rule) => ({
    id: rule.id,
    name: rule.name,
    description: rule.description,
    severity: rule.severity,
    mitre: [...rule.mitre],
    pattern: rule.pattern instanceof RegExp ? rule.pattern.source : String(rule.pattern || ""),
    patternFlags: rule.pattern instanceof RegExp ? rule.pattern.flags : "gi",
    altPatterns: (rule.altPatterns || []).map(p => p instanceof RegExp ? p.source : String(p)).join("\n"),
    keywords: [...(rule.keywords || [])],
    nextSteps: [...(rule.nextSteps || [])],
    logType: rule.logType || "windows_event_log"
  });

  const formToRule = (form) => {
    let pattern;
    try { pattern = new RegExp(form.pattern, form.patternFlags || "gi"); }
    catch { pattern = new RegExp(form.pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), "gi"); }
    const altPatterns = form.altPatterns.split("\n").filter(s => s.trim()).map(s => {
      try { return new RegExp(s.trim(), "gi"); }
      catch { return new RegExp(s.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), "gi"); }
    });
    return {
      id: form.id.trim(),
      name: form.name.trim(),
      description: form.description.trim(),
      severity: form.severity,
      mitre: form.mitre.filter(s => s.trim()),
      pattern,
      altPatterns,
      keywords: form.keywords.filter(s => s.trim()),
      nextSteps: form.nextSteps.filter(s => s.trim())
    };
  };

  const validateRegex = (src) => {
    if (!src.trim()) return { valid: false, error: "Pattern is required" };
    try { new RegExp(src); return { valid: true }; }
    catch (e) { return { valid: false, error: e.message }; }
  };

  const openNewRule = (logType) => {
    const form = makeEmptyRule(logType);
    // Auto-generate next ID
    const existing = customRules[logType] || [];
    const prefix = { windows_event_log: "WIN", web_server_log: "WEB", registry: "REG" }[logType] || "RUL";
    const nums = existing.map(r => { const m = r.id.match(/(\d+)$/); return m ? parseInt(m[1]) : 0; });
    const next = (Math.max(0, ...nums) + 1).toString().padStart(3, "0");
    form.id = `${prefix}-${next}`;
    form.patternFlags = "gi";
    setEditingRule({ form, isNew: true, originalLogType: logType, originalId: null });
    setShowRuleEditor(true);
  };

  const openEditRule = (rule) => {
    setEditingRule({ form: ruleToForm(rule), isNew: false, originalLogType: rule.logType, originalId: rule.id });
    setShowRuleEditor(true);
  };

  // ── Backend Rule Sync ───────────────────────────────────────────────
  const loadRulesFromBackend = useCallback(async () => {
    try {
      const res = await fetch(`${backendUrl}/rules?grouped=true`);
      const data = await res.json();
      if (data.status === "success" && data.rules) {
        const hydrated = {};
        for (const [logType, rules] of Object.entries(data.rules)) {
          hydrated[logType] = rules.map(r => {
            let mainPattern;
            try { mainPattern = new RegExp(r.pattern || ".", "gi"); } catch { mainPattern = /./gi; }
            const altPatterns = (r.alt_patterns || []).map(p => {
              try { return new RegExp(p, "gi"); } catch { return /./gi; }
            });
            return {
              id: r.id,
              name: r.name,
              description: r.description || "",
              severity: r.severity || "medium",
              logType: logType,
              mitre: r.mitre || [],
              pattern: mainPattern,
              altPatterns: altPatterns,
              keywords: r.keywords || [],
              nextSteps: r.next_steps || [],
              providerFilter: r.provider_filter ? (() => { try { return new RegExp(r.provider_filter, "i"); } catch { return null; } })() : null,
              providerExclude: r.provider_exclude ? (() => { try { return new RegExp(r.provider_exclude, "i"); } catch { return null; } })() : null,
              countThreshold: r.count_threshold || null,
              sigmaSource: r.sigma_source || null,
              isBuiltin: r.is_builtin || false,
              isEnabled: r.is_enabled !== false,
            };
          });
        }
        setCustomRules(hydrated);
        return true;
      }
    } catch (err) {
      console.warn("Failed to load rules from backend:", err);
    }
    return false;
  }, [backendUrl]);

  // Load rules from backend on mount
  useEffect(() => { loadRulesFromBackend(); }, [loadRulesFromBackend]);

  const saveRule = async () => {
    if (!editingRule) return;
    const { form, isNew, originalLogType, originalId } = editingRule;
    const newRule = formToRule(form);
    const logType = form.logType;
    try {
      const rulePayload = {
        id: form.id, name: form.name.trim(), description: form.description?.trim() || "",
        severity: form.severity, log_type: logType,
        mitre: form.mitre.filter(s => s.trim()), pattern: form.pattern,
        alt_patterns: form.altPatterns.split("\n").filter(s => s.trim()),
        keywords: form.keywords.filter(s => s.trim()),
        next_steps: form.nextSteps.filter(s => s.trim()),
      };
      if (isNew) {
        const res = await fetch(`${backendUrl}/rules`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify(rulePayload)
        });
        if ((await res.json()).status === "success") { await loadRulesFromBackend(); setShowRuleEditor(false); setEditingRule(null); return; }
      } else {
        const res = await fetch(`${backendUrl}/rules/${originalId || form.id}`, {
          method: "PUT", headers: { "Content-Type": "application/json" },
          body: JSON.stringify(rulePayload)
        });
        if ((await res.json()).status === "success") { await loadRulesFromBackend(); setShowRuleEditor(false); setEditingRule(null); return; }
      }
    } catch (err) { console.warn("Backend rule save failed, saving locally:", err); }
    // Fallback local
    setCustomRules(prev => {
      const next = { ...prev };
      if (!isNew && originalId) next[originalLogType] = (next[originalLogType] || []).filter(r => r.id !== originalId);
      if (!next[logType]) next[logType] = [];
      if (isNew) next[logType] = [...next[logType], newRule];
      else { const idx = next[logType].findIndex(r => r.id === newRule.id); if (idx >= 0) { next[logType] = [...next[logType]]; next[logType][idx] = newRule; } else next[logType] = [...next[logType], newRule]; }
      return next;
    });
    setShowRuleEditor(false); setEditingRule(null);
  };

  const deleteRule = async (rule) => {
    if (!confirm(`Delete rule "${rule.name}" (${rule.id})?`)) return;
    try { await fetch(`${backendUrl}/rules/${rule.id}`, { method: "DELETE" }); await loadRulesFromBackend(); }
    catch (err) { console.warn("Backend delete failed:", err); setCustomRules(prev => { const next = { ...prev }; next[rule.logType] = (next[rule.logType] || []).filter(r => r.id !== rule.id); return next; }); }
    setRuleExpanded(null);
  };

  const resetRules = async () => {
    if (!confirm("Reset all rules to defaults? Custom rules will be lost.")) return;
    try { await fetch(`${backendUrl}/rules/reset`, { method: "POST" }); await loadRulesFromBackend(); return; }
    catch (err) { console.warn("Backend reset failed:", err); }
    const clone = {};
    for (const [key, rules] of Object.entries(DETECTION_RULES)) {
      clone[key] = rules.map(r => ({ ...r, pattern: new RegExp(r.pattern.source, r.pattern.flags), altPatterns: r.altPatterns ? r.altPatterns.map(p => new RegExp(p.source, p.flags)) : [], keywords: [...(r.keywords || [])], mitre: [...(r.mitre || [])], nextSteps: [...(r.nextSteps || [])] }));
    }
    setCustomRules(clone);
  };

  const exportRules = () => {
    const exportData = {};
    for (const [key, rules] of Object.entries(customRules)) {
      exportData[key] = rules.map(r => ({ ...r, pattern: r.pattern instanceof RegExp ? { source: r.pattern.source, flags: r.pattern.flags } : r.pattern, altPatterns: (r.altPatterns || []).map(p => p instanceof RegExp ? { source: p.source, flags: p.flags } : p) }));
    }
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url;
    a.download = `sigil_rules_${new Date().toISOString().slice(0,10)}.json`; a.click(); URL.revokeObjectURL(url);
  };

  const importRulesFromFile = (e) => {
    const file = e.target.files?.[0]; if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      try {
        const data = JSON.parse(ev.target.result); const imported = {};
        for (const [key, rules] of Object.entries(data)) {
          if (!Array.isArray(rules)) continue;
          imported[key] = rules.map(r => ({ ...r, pattern: new RegExp(r.pattern?.source || r.pattern || ".", r.pattern?.flags || "gi"), altPatterns: (r.altPatterns || []).map(p => new RegExp(p?.source || p || ".", p?.flags || "gi")), keywords: r.keywords || [], mitre: r.mitre || [], nextSteps: r.nextSteps || [] }));
        }
        setCustomRules(imported); alert(`Imported ${Object.values(imported).flat().length} rules successfully.`);
      } catch (err) { alert("Failed to import rules: " + err.message); }
    };
    reader.readAsText(file); e.target.value = "";
  };

  const importSigmaRules = async (e) => {
    const files = Array.from(e.target.files || []); if (files.length === 0) return;
    try {
      let totalImported = 0, totalErrors = 0, totalDuplicates = 0;
      for (const file of files) {
        const formData = new FormData(); formData.append("file", file);
        const res = await fetch(`${backendUrl}/rules/import-sigma`, { method: "POST", body: formData });
        const data = await res.json();
        if (data.status === "success") {
          totalImported += data.imported;
          totalDuplicates += (data.duplicates || 0);
        } else totalErrors++;
      }
      await loadRulesFromBackend();
      const parts = [`Imported ${totalImported} Sigma rule${totalImported !== 1 ? "s" : ""}`];
      if (totalDuplicates > 0) parts.push(`${totalDuplicates} duplicate${totalDuplicates !== 1 ? "s" : ""} skipped`);
      if (totalErrors > 0) parts.push(`${totalErrors} failed`);
      alert(parts.join(", ") + ".");
    } catch (err) {
      alert("Sigma import failed: backend is unreachable. Please check the backend connection.");
      console.error("Sigma import failed:", err);
    }
    e.target.value = "";
  };


  // ── Case Management ─────────────────────────────────────────────────
  const serializeCase = () => {
    // Strip raw content from artifacts for file size — keep parsed events and metadata
    const lightArtifacts = artifacts.map(a => ({
      name: a.name, size: a.size, logType: a.logType, timestamp: a.timestamp,
      parsedBackend: a.parsedBackend, eventCount: a.eventCount,
      content: a.content,
      events: a.events || null
    }));
    // Strip regex from findings for serialization
    const lightFindings = findings.map(f => ({
      ...f,
      pattern: f.pattern instanceof RegExp ? f.pattern.source : f.pattern,
      altPatterns: (f.altPatterns || []).map(p => p instanceof RegExp ? p.source : p),
    }));
    return {
      sigil_version: "1.0.0",
      case: { ...caseMeta, savedAt: new Date().toISOString() },
      artifacts: lightArtifacts,
      findings: lightFindings,
      overallScore,
      iocList: iocList,
      iocEnabled: iocEnabled,
      bookmarkedEvents: [...bookmarkedEvents]
    };
  };

  const saveCase = () => {
    const data = serializeCase();
    const blob = new Blob([JSON.stringify(data)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const safeName = (caseMeta.name || "untitled").replace(/[^a-zA-Z0-9_-]/g, "_").toLowerCase();
    a.href = url;
    a.download = `sigil_case_${safeName}_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const importCase = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      try {
        const data = JSON.parse(ev.target.result);
        if (!data.sigil_version) throw new Error("Not a valid SIGIL case file");
        if (data.case) setCaseMeta(data.case);
        if (data.artifacts) setArtifacts(data.artifacts);
        if (data.findings) {
          setFindings(data.findings);
          if (data.findings.length > 0) setExpandedFindings(new Set([data.findings[0].uid || data.findings[0].id]));
        }
        if (data.overallScore) setOverallScore(data.overallScore);
        if (data.iocList) setIocList(data.iocList);
        if (data.iocEnabled !== undefined) setIocEnabled(data.iocEnabled);
        if (data.bookmarkedEvents) setBookmarkedEvents(new Set(data.bookmarkedEvents));
        else if (data.bookmarkedFindings) setBookmarkedEvents(new Set(data.bookmarkedFindings)); // backward compat
        setActiveTab("analyze");
        setTimelinePage(0);
      } catch (err) {
        alert("Failed to import case: " + err.message);
      }
    };
    reader.readAsText(file);
    e.target.value = "";
  };

  const hasActiveCase = caseMeta.name && caseMeta.name.trim().length > 0;

  // ── IOC Management ─────────────────────────────────────────────────────
  const detectIocType = (value) => {
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value)) return "ip";
    if (/^[a-fA-F0-9:]+$/.test(value) && value.includes(":")) return "ip"; // IPv6
    if (/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/\d{1,2}$/.test(value)) return "ip"; // CIDR
    return "domain";
  };

  const addIocs = (text) => {
    const values = text.split(/[\n,;\s]+/).map(v => v.trim().toLowerCase()).filter(v => v && v.length > 2);
    const newIocs = [];
    for (const v of values) {
      const clean = v.replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/:\d+$/, "");
      if (!clean || clean.length < 3) continue;
      if (iocList.some(ioc => ioc.value === clean)) continue;
      newIocs.push({ value: clean, type: detectIocType(clean) });
    }
    if (newIocs.length > 0) setIocList(prev => [...prev, ...newIocs]);
    return newIocs.length;
  };

  const importIocFile = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const count = addIocs(ev.target.result);
      alert(`Imported ${count} IOC${count !== 1 ? "s" : ""}.`);
    };
    reader.readAsText(file);
    e.target.value = "";
  };

  const removeIoc = (value) => setIocList(prev => prev.filter(i => i.value !== value));
  const clearIocs = () => setIocList([]);

  // Build IOC detection rule dynamically
  // ── Tag Input Component ────────────────────────────────────────────────
  const TagInput = ({ tags, onChange, placeholder }) => {
    const [input, setInput] = useState("");
    const addTag = () => {
      const val = input.trim();
      if (val && !tags.includes(val)) { onChange([...tags, val]); }
      setInput("");
    };
    return (
      <div className="tag-input-container" onClick={(e) => e.currentTarget.querySelector("input")?.focus()}>
        {tags.map((tag, i) => (
          <span key={i} className="tag-item">
            {tag}
            <button onClick={() => onChange(tags.filter((_, j) => j !== i))}>×</button>
          </span>
        ))}
        <input
          className="tag-input"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === ",") { e.preventDefault(); addTag(); }
            if (e.key === "Backspace" && !input && tags.length) { onChange(tags.slice(0, -1)); }
          }}
          onBlur={addTag}
          placeholder={tags.length === 0 ? placeholder : ""}
        />
      </div>
    );
  };

  // ── Rule Editor Modal ──────────────────────────────────────────────────
  const RuleEditorModal = () => {
    if (!showRuleEditor || !editingRule) return null;
    const { form, isNew } = editingRule;
    const patternCheck = validateRegex(form.pattern);
    const canSave = form.id.trim() && form.name.trim() && form.pattern.trim() && patternCheck.valid;
    const updateForm = (updates) => {
      setEditingRule(prev => ({ ...prev, form: { ...prev.form, ...updates } }));
    };
    return (
      <div className="modal-overlay" onClick={() => setShowRuleEditor(false)}>
        <div className="modal-content" onClick={(e) => e.stopPropagation()}>
          <div className="modal-header">
            <h3>{isNew ? "Create New Rule" : `Edit Rule — ${form.id}`}</h3>
            <button className="modal-close" onClick={() => setShowRuleEditor(false)}>×</button>
          </div>
          <div className="modal-body">
            {/* Row: ID + Severity + Log Type */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
              <div className="form-group">
                <label className="form-label">Rule ID</label>
                <input className="form-input" value={form.id} onChange={(e) => updateForm({ id: e.target.value })} placeholder="WIN-012" />
              </div>
              <div className="form-group">
                <label className="form-label">Severity</label>
                <select className="form-select" value={form.severity} onChange={(e) => updateForm({ severity: e.target.value })}>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>
              <div className="form-group">
                <label className="form-label">Log Type</label>
                <select className="form-select" value={form.logType} onChange={(e) => updateForm({ logType: e.target.value })}>
                  <option value="windows_event_log">Windows Events</option>
                  <option value="web_server_log">Web Server</option>
                  <option value="registry">Registry</option>
                </select>
              </div>
            </div>
            {/* Name */}
            <div className="form-group">
              <label className="form-label">Rule Name</label>
              <input className="form-input" value={form.name} onChange={(e) => updateForm({ name: e.target.value })} placeholder="Suspicious Activity Name" />
            </div>
            {/* Description */}
            <div className="form-group">
              <label className="form-label">Description</label>
              <textarea className="form-textarea" value={form.description} onChange={(e) => updateForm({ description: e.target.value })} placeholder="Describe what this rule detects and why it matters..." />
            </div>
            {/* Primary Pattern */}
            <div className="form-group">
              <label className="form-label">Primary Regex Pattern</label>
              <div className="form-row">
                <input
                  className={`form-input ${form.pattern.trim() ? (patternCheck.valid ? "regex-valid" : "regex-invalid") : ""}`}
                  value={form.pattern}
                  onChange={(e) => updateForm({ pattern: e.target.value })}
                  placeholder="(?:4625.*){3,}"
                  style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}
                />
                <input
                  className="form-input"
                  value={form.patternFlags || "gi"}
                  onChange={(e) => updateForm({ patternFlags: e.target.value })}
                  placeholder="gi"
                  style={{ maxWidth: 80, textAlign: "center" }}
                />
              </div>
              {form.pattern.trim() && (
                <div className={`regex-status ${patternCheck.valid ? "valid" : "invalid"}`}>
                  {patternCheck.valid ? "✓ Valid regex" : `✗ ${patternCheck.error}`}
                </div>
              )}
              <div className="form-hint">Regular expression without delimiters. Flags in the right field (default: gi).</div>
            </div>
            {/* Alt Patterns */}
            <div className="form-group">
              <label className="form-label">Alternative Patterns (one per line)</label>
              <textarea
                className="form-textarea"
                value={form.altPatterns}
                onChange={(e) => updateForm({ altPatterns: e.target.value })}
                placeholder={"event[_\\s]?id[:=]*4625\nan account failed to log on"}
                style={{ fontFamily: "var(--font-mono)", fontSize: 12, minHeight: 70 }}
              />
              <div className="form-hint">Additional regex patterns that strengthen confidence. One regex per line, no delimiters.</div>
            </div>
            {/* Keywords */}
            <div className="form-group">
              <label className="form-label">Keywords</label>
              <TagInput tags={form.keywords} onChange={(keywords) => updateForm({ keywords })} placeholder="Type a keyword and press Enter" />
              <div className="form-hint">Case-insensitive keyword matches that add to confidence scoring.</div>
            </div>
            {/* MITRE */}
            <div className="form-group">
              <label className="form-label">MITRE ATT&CK Techniques</label>
              <TagInput tags={form.mitre} onChange={(mitre) => updateForm({ mitre })} placeholder="T1059, T1027..." />
              <div className="form-hint">MITRE ATT&CK technique IDs (e.g., T1059, T1078).</div>
            </div>
            {/* Next Steps */}
            <div className="form-group">
              <label className="form-label">Suggested Next Steps</label>
              {form.nextSteps.map((step, i) => (
                <div key={i} style={{ display: "flex", gap: 8, marginBottom: 6 }}>
                  <span style={{ color: "var(--accent-cyan)", fontFamily: "var(--font-mono)", fontSize: 12, paddingTop: 10, flexShrink: 0 }}>→</span>
                  <input
                    className="form-input"
                    value={step}
                    onChange={(e) => {
                      const ns = [...form.nextSteps];
                      ns[i] = e.target.value;
                      updateForm({ nextSteps: ns });
                    }}
                    placeholder="Describe next step..."
                  />
                  <button
                    className="btn-ghost"
                    style={{ color: "var(--accent-red)", flexShrink: 0, padding: "8px 6px" }}
                    onClick={() => updateForm({ nextSteps: form.nextSteps.filter((_, j) => j !== i) })}
                    title="Remove step"
                  >×</button>
                </div>
              ))}
              <button className="btn btn-ghost" style={{ fontSize: 12, color: "var(--accent-blue)" }}
                onClick={() => updateForm({ nextSteps: [...form.nextSteps, ""] })}>
                + Add Step
              </button>
            </div>
          </div>
          <div className="modal-footer">
            <button className="btn btn-secondary" onClick={() => setShowRuleEditor(false)}>Cancel</button>
            <div style={{ display: "flex", gap: 8 }}>
              <button className="btn btn-primary" onClick={saveRule} disabled={!canSave}>
                {isNew ? "Create Rule" : "Save Changes"}
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  };

  // ── Evidence Viewer Modal ──────────────────────────────────────────────
  const [evExpandedRows, setEvExpandedRows] = useState(new Set());
  const [evSearchFilter, setEvSearchFilter] = useState("");
  const evScrollRef = useRef(null);

  // Reset evidence viewer state when opening a new finding
  const openEvidenceViewer = useCallback((finding) => {
    setEvExpandedRows(new Set());
    setEvSearchFilter("");
    setEvidenceViewer({ finding });
  }, []);

  const EvidenceViewerModal = () => {
    if (!evidenceViewer) return null;
    const { finding } = evidenceViewer;
    const events = finding.matchedEvents || [];
    
    const filtered = evSearchFilter.trim()
      ? events.filter(e => {
          const s = evSearchFilter.toLowerCase();
          const f = e.structuredFields || e.fields || {};
          return (e.content || "").toLowerCase().includes(s) ||
            (e.eventId || "").includes(s) ||
            (e.recordId || "").includes(s) ||
            (e.event_id || "").includes(s) ||
            (e.record_id || "").includes(s) ||
            (e.message || "").toLowerCase().includes(s) ||
            (f.ip || "").toLowerCase().includes(s) ||
            (f.method || "").toLowerCase().includes(s) ||
            (f.status || "").includes(s) ||
            (f.uri || "").toLowerCase().includes(s) ||
            (f.userAgent || "").toLowerCase().includes(s);
        })
      : events;

    const toggleRow = (idx) => {
      const scrollPos = evScrollRef.current?.scrollTop || 0;
      setEvExpandedRows(prev => {
        const next = new Set(prev);
        next.has(idx) ? next.delete(idx) : next.add(idx);
        return next;
      });
      // Double-RAF: first waits for React commit, second waits for DOM paint
      requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          if (evScrollRef.current) evScrollRef.current.scrollTop = scrollPos;
        });
      });
    };

    const highlightContent = (text, maxLen = 200) => {
      if (!text) return "";
      const display = evExpandedRows.has("full") ? text : text.slice(0, maxLen);
      // Highlight keywords from the rule
      let highlighted = display;
      const kws = (finding.keywords || []).slice(0, 8);
      for (const kw of kws) {
        if (kw.length < 2) continue;
        try {
          const re = new RegExp(`(${kw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
          highlighted = highlighted.replace(re, '◆$1◆');
        } catch {}
      }
      return highlighted.split('◆').map((part, i) => {
        if (i % 2 === 1) return <mark key={i}>{part}</mark>;
        return part;
      });
    };

    return (
      <div className="modal-overlay evidence-modal" onClick={() => setEvidenceViewer(null)}>
        <div className="modal-content" onClick={(e) => e.stopPropagation()}>
          <div className="modal-header">
            <div>
              <h3 style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span className={`severity-dot severity-${finding.severity}`} />
                {finding.name}
                <span style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)", fontWeight: 400 }}>{finding.id}</span>
              </h3>
            </div>
            <button className="modal-close" onClick={() => setEvidenceViewer(null)}>×</button>
          </div>
          <div className="evidence-stats">
            <div>Matched events: <span>{events.length}</span></div>
            <div>Source: <span>{finding.source}</span></div>
            <div>Confidence: <span>{finding.confidence}%</span></div>
            {filtered.length !== events.length && <div>Showing: <span>{filtered.length}</span> filtered</div>}
            {finding._timelineClick && (() => {
              const fullFinding = findings.find(f => (f.uid || f.id) === (finding.uid || finding.id));
              const totalCount = fullFinding ? (fullFinding.matchedEvents || []).length : 0;
              return totalCount > 1 ? (
                <button
                  className="btn btn-ghost"
                  style={{ fontSize: 11, color: "var(--accent-blue)", marginLeft: "auto" }}
                  onClick={() => setEvidenceViewer({ finding: fullFinding })}
                >
                  View all {totalCount} events →
                </button>
              ) : null;
            })()}
          </div>
          <div className="evidence-search">
            <input
              placeholder={finding.logType === "web_server_log" ? "Filter by IP, method, status code, URI, or content..." : "Filter by Event ID, Record ID, or content..."}
              value={evSearchFilter}
              onChange={(e) => setEvSearchFilter(e.target.value)}
            />
          </div>
          <div ref={evScrollRef} style={{ overflowY: "auto", maxHeight: "calc(90vh - 200px)" }}>
            {filtered.length === 0 ? (
              <div className="empty-state" style={{ padding: 40 }}>
                <p>{events.length === 0 ? "No event-level evidence captured for this finding." : "No events match your filter."}</p>
              </div>
            ) : (
              <table className="evidence-table">
                <thead>
                  <tr>
                    <th style={{ width: 30 }}>☆</th>
                    <th style={{ width: 30 }}>#</th>
                    {finding.logType === "web_server_log" ? (
                      <>
                        <th style={{ width: 60 }}>Line</th>
                        <th style={{ width: 120 }}>IP</th>
                        <th style={{ width: 50 }}>Method</th>
                        <th style={{ width: 50 }}>Status</th>
                        <th style={{ width: 150 }}>Timestamp</th>
                        <th>URI / Content</th>
                      </>
                    ) : (
                      <>
                        <th style={{ width: 70 }}>Record ID</th>
                        <th style={{ width: 70 }}>Event ID</th>
                        <th style={{ width: 160 }}>Timestamp</th>
                        <th>Content</th>
                      </>
                    )}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((ev, idx) => {
                    const rid = ev.recordId || ev.record_id || "—";
                    const eid = ev.eventId || ev.event_id || "—";
                    const ts = ev.timestamp || "—";
                    const isExpanded = evExpandedRows.has(idx);
                    const contentText = ev.content || ev.message || "";
                    const fields = ev.structuredFields || ev.fields || null;
                    const isWeb = finding.logType === "web_server_log";
                    const evBookmarkKey = `${finding.uid || finding.id}:${rid}`;
                    const isBookmarked = bookmarkedEvents.has(evBookmarkKey);

                    return (
                      <tr key={idx} className={`severity-row-${finding.severity}`} style={isBookmarked ? { background: "rgba(245, 158, 11, 0.08)" } : {}}>
                        <td style={{ textAlign: "center", cursor: "pointer", fontSize: 16 }}
                          onClick={() => toggleEventBookmark(finding.uid || finding.id, rid)}
                          title={isBookmarked ? "Remove bookmark" : "Bookmark this event for report"}>
                          <span style={{ color: isBookmarked ? "var(--accent-orange)" : "var(--text-muted)", opacity: isBookmarked ? 1 : 0.3 }}>
                            {isBookmarked ? "★" : "☆"}
                          </span>
                        </td>
                        <td style={{ color: "var(--text-muted)", fontSize: 10 }}>{idx + 1}</td>
                        {isWeb ? (
                          <>
                            <td><span className="evidence-record-id">{rid}</span></td>
                            <td><span style={{ color: "var(--text-primary)", fontFamily: "var(--font-mono)", fontSize: 11 }}>{fields?.ip || "—"}</span></td>
                            <td><span style={{ color: fields?.method === "POST" ? "var(--accent-orange)" : "var(--accent-cyan)", fontFamily: "var(--font-mono)", fontSize: 11, fontWeight: 600 }}>{fields?.method || "—"}</span></td>
                            <td><span style={{ color: fields?.status?.startsWith("2") ? "var(--accent-green)" : fields?.status?.startsWith("4") ? "var(--accent-orange)" : fields?.status?.startsWith("5") ? "var(--accent-red)" : "var(--text-muted)", fontFamily: "var(--font-mono)", fontSize: 11, fontWeight: 600 }}>{fields?.status || "—"}</span></td>
                            <td><span className="evidence-timestamp">{ts}</span></td>
                            <td className="evidence-content">
                              {highlightContent(fields?.uri || contentText, isExpanded ? 99999 : 120)}
                              {(contentText.length > 120 || (fields && Object.keys(fields).length > 3)) && (
                                <button className="evidence-expand-btn" onClick={() => toggleRow(idx)}>
                                  {isExpanded ? "▲ Collapse" : "▼ Show more"}
                                </button>
                              )}
                              {isExpanded && (
                                <div className="evidence-fields">
                                  {fields?.userAgent && fields.userAgent !== "-" && <div><span className="field-name">User-Agent:</span><span className="field-value">{fields.userAgent}</span></div>}
                                  {fields?.referer && fields.referer !== "-" && <div><span className="field-name">Referer:</span><span className="field-value">{fields.referer}</span></div>}
                                  {fields?.size && fields.size !== "-" && <div><span className="field-name">Size:</span><span className="field-value">{fields.size}</span></div>}
                                  {fields?.serverIp && <div><span className="field-name">Server IP:</span><span className="field-value">{fields.serverIp}</span></div>}
                                  {fields?.port && <div><span className="field-name">Port:</span><span className="field-value">{fields.port}</span></div>}
                                  <div style={{ marginTop: 4, borderTop: "1px solid var(--border-primary)", paddingTop: 4 }}>
                                    <span className="field-name">Raw:</span><span className="field-value">{contentText.length > 500 ? contentText.slice(0, 500) + "…" : contentText}</span>
                                  </div>
                                </div>
                              )}
                            </td>
                          </>
                        ) : (
                          <>
                            <td><span className="evidence-record-id">{rid}</span></td>
                            <td><span className="evidence-event-id">{eid}</span></td>
                            <td><span className="evidence-timestamp">{ts}</span></td>
                            <td className="evidence-content">
                              {/* Collapsed: show brief summary */}
                              {!isExpanded && (
                                <div style={{ fontSize: 11, fontFamily: "var(--font-mono)" }}>
                                  {fields?.ScriptBlockText ? (
                                    <span>{fields.ScriptBlockText.slice(0, 150)}{fields.ScriptBlockText.length > 150 ? "…" : ""}</span>
                                  ) : fields && Object.keys(fields).length > 0 ? (
                                    Object.entries(fields).slice(0, 2).map(([k, v]) => (
                                      <div key={k} style={{ marginBottom: 2 }}>
                                        <span style={{ color: "var(--accent-cyan)" }}>{k}: </span>
                                        <span style={{ wordBreak: "break-all" }}>{v && v.length > 100 ? v.slice(0, 100) + "…" : v}</span>
                                      </div>
                                    ))
                                  ) : (
                                    <span>{contentText.slice(0, 150)}{contentText.length > 150 ? "…" : ""}</span>
                                  )}
                                </div>
                              )}
                              {/* Expanded: show full EventData XML or full fields */}
                              {isExpanded && (
                                <div>
                                  {ev.eventDataXml ? (
                                    <div>
                                      <span style={{ fontSize: 9, color: "var(--accent-cyan)", fontFamily: "var(--font-mono)", fontWeight: 600 }}>EVENT XML:</span>
                                      <pre style={{ fontSize: 10, fontFamily: "var(--font-mono)", color: "var(--text-secondary)", background: "var(--bg-primary)", padding: 8, borderRadius: 4, marginTop: 4, whiteSpace: "pre-wrap", wordBreak: "break-all", maxHeight: 500, overflowY: "auto", border: "1px solid var(--border-primary)" }}>
                                        {ev.eventDataXml}
                                      </pre>
                                    </div>
                                  ) : fields && Object.keys(fields).length > 0 ? (
                                    <div className="evidence-fields">
                                      {Object.entries(fields).map(([k, v]) => (
                                        <div key={k}>
                                          <span className="field-name">{k}:</span>
                                          <span className="field-value" style={{ wordBreak: "break-all" }}>{v}</span>
                                        </div>
                                      ))}
                                    </div>
                                  ) : (
                                    <div style={{ fontSize: 11, fontFamily: "var(--font-mono)", wordBreak: "break-all" }}>{contentText}</div>
                                  )}
                                </div>
                              )}
                              <button className="evidence-expand-btn" onClick={() => toggleRow(idx)}>
                                {isExpanded ? "▲ Collapse" : `▼ Show more${ev.eventDataXml ? " (Event XML)" : ""}${ev.context?.length ? ` (+${ev.context.length} context)` : ""}`}
                              </button>
                              {isExpanded && !ev.eventDataXml && ev.context && ev.context.length > 0 && (
                                <div style={{ marginTop: 6, paddingTop: 6, borderTop: "1px dashed var(--border-primary)" }}>
                                  <span style={{ fontSize: 9, color: "var(--accent-purple)", fontFamily: "var(--font-mono)", fontWeight: 600 }}>CONTEXT (lines below match):</span>
                                  {ev.context.map((ctx, ci) => (
                                    <div key={ci} style={{ fontSize: 11, fontFamily: "var(--font-mono)", color: "var(--text-secondary)", padding: "2px 0 2px 12px", borderLeft: "2px solid var(--accent-purple)", marginTop: 3 }}>
                                      {highlightContent(ctx, 200)}
                                    </div>
                                  ))}
                                </div>
                              )}
                            </td>
                          </>
                        )}
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>
    );
  };

  // ── Timeline Builder ───────────────────────────────────────────────────
  const [timelinePage, setTimelinePage] = useState(0);
  const [timelineSevFilter, setTimelineSevFilter] = useState("all");
  const TIMELINE_PAGE_SIZE = 100;

  const buildTimeline = () => {
    if (!findings.length) return [];
    const events = [];
    for (const f of findings) {
      if (!f.matchedEvents || f.matchedEvents.length === 0) {
        events.push({
          timestamp: null,
          findingId: f.id,
          findingName: f.name,
          severity: f.severity,
          eventId: null,
          recordId: null,
          source: f.source,
          finding: f
        });
        continue;
      }
      for (const ev of f.matchedEvents) {
        events.push({
          timestamp: ev.timestamp || null,
          findingId: f.id,
          findingName: f.name,
          severity: f.severity,
          eventId: ev.eventId || ev.event_id || null,
          recordId: ev.recordId || ev.record_id || null,
          source: f.source,
          finding: f,
          event: ev
        });
      }
    }
    events.sort((a, b) => {
      if (!a.timestamp && !b.timestamp) return 0;
      if (!a.timestamp) return 1;
      if (!b.timestamp) return -1;
      return a.timestamp.localeCompare(b.timestamp);
    });
    return events;
  };

  const totalTimelineEvents = () => {
    let count = 0;
    for (const f of findings) count += (f.matchedEvents || []).length || 1;
    return count;
  };

  return (
    <div>
      <style>{STYLES}</style>

      {/* ═══ CASE GATE — shown when no case is active ═══ */}
      {!caseActive && (
        <div className="app-container" style={{ display: "flex", alignItems: "center", justifyContent: "center", minHeight: "100vh" }}>
          <div style={{ maxWidth: 520, width: "100%", padding: 32 }}>
            {/* Logo */}
            <div style={{ textAlign: "center", marginBottom: 32 }}>
              <div className="logo-mark" style={{ margin: "0 auto 12px", width: 56, height: 56, borderRadius: 14, display: "flex", alignItems: "center", justifyContent: "center" }}><Icons.Shield /></div>
              <h1 style={{ fontSize: 28, fontFamily: "var(--font-display)", margin: 0 }}>SIGIL</h1>
              <p style={{ color: "var(--text-muted)", fontSize: 12, fontFamily: "var(--font-mono)", marginTop: 4 }}>DFIR Compromise Assessment Tool</p>
            </div>

            {caseScreen === "gate" && (
              <div>
                <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                  <button className="btn btn-primary" onClick={() => setCaseScreen("create")}
                    style={{ padding: "14px 24px", fontSize: 14, width: "100%" }}>
                    + New Case
                  </button>
                  <button className="btn btn-secondary" onClick={openCaseFromDisk}
                    disabled={caseLoading}
                    style={{ padding: "14px 24px", fontSize: 14, width: "100%" }}>
                    {caseLoading ? "Opening..." : "Open Existing Case"}
                  </button>
                </div>
                <p style={{ textAlign: "center", color: "var(--text-muted)", fontSize: 11, marginTop: 20, lineHeight: 1.6 }}>
                  Create a new case or open an existing .sigil case file.<br />
                  All evidence, findings, and bookmarks are saved to the case folder.
                </p>
              </div>
            )}

            {caseScreen === "create" && (
              <div style={{ background: "var(--bg-card)", border: "1px solid var(--border-primary)", borderRadius: 8, padding: 24 }}>
                <h3 style={{ margin: "0 0 16px", fontSize: 15 }}>Create New Case</h3>
                <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                  <div>
                    <label style={{ fontSize: 11, color: "var(--text-muted)", display: "block", marginBottom: 4, fontFamily: "var(--font-mono)" }}>Case Name *</label>
                    <input type="text" value={newCaseName} onChange={e => setNewCaseName(e.target.value)}
                      placeholder="e.g. Incident Response - Server Compromise"
                      style={{ width: "100%", padding: "8px 12px", background: "var(--bg-primary)", border: "1px solid var(--border-primary)", borderRadius: 6, color: "var(--text-primary)", fontSize: 13 }} />
                  </div>
                  <div>
                    <label style={{ fontSize: 11, color: "var(--text-muted)", display: "block", marginBottom: 4, fontFamily: "var(--font-mono)" }}>Examiner *</label>
                    <input type="text" value={newCaseExaminer} onChange={e => setNewCaseExaminer(e.target.value)}
                      placeholder="e.g. Rodel"
                      style={{ width: "100%", padding: "8px 12px", background: "var(--bg-primary)", border: "1px solid var(--border-primary)", borderRadius: 6, color: "var(--text-primary)", fontSize: 13 }} />
                  </div>
                  <div>
                    <label style={{ fontSize: 11, color: "var(--text-muted)", display: "block", marginBottom: 4, fontFamily: "var(--font-mono)" }}>Organization</label>
                    <input type="text" value={newCaseOrg} onChange={e => setNewCaseOrg(e.target.value)}
                      placeholder="e.g. OWWA"
                      style={{ width: "100%", padding: "8px 12px", background: "var(--bg-primary)", border: "1px solid var(--border-primary)", borderRadius: 6, color: "var(--text-primary)", fontSize: 13 }} />
                  </div>
                  <div>
                    <label style={{ fontSize: 11, color: "var(--text-muted)", display: "block", marginBottom: 4, fontFamily: "var(--font-mono)" }}>Description</label>
                    <textarea value={newCaseDesc} onChange={e => setNewCaseDesc(e.target.value)}
                      placeholder="Brief case description..."
                      rows={2}
                      style={{ width: "100%", padding: "8px 12px", background: "var(--bg-primary)", border: "1px solid var(--border-primary)", borderRadius: 6, color: "var(--text-primary)", fontSize: 13, resize: "vertical" }} />
                  </div>
                  <div>
                    <label style={{ fontSize: 11, color: "var(--text-muted)", display: "block", marginBottom: 4, fontFamily: "var(--font-mono)" }}>Save Location *</label>
                    <div style={{ display: "flex", gap: 8 }}>
                      <input type="text" value={newCasePath} onChange={e => setNewCasePath(e.target.value)}
                        placeholder="Select folder..."
                        style={{ flex: 1, padding: "8px 12px", background: "var(--bg-primary)", border: "1px solid var(--border-primary)", borderRadius: 6, color: "var(--text-primary)", fontSize: 13 }} />
                      <button className="btn btn-secondary" onClick={browseCaseFolder} style={{ whiteSpace: "nowrap" }}>Browse</button>
                    </div>
                  </div>
                  <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
                    <button className="btn btn-secondary" onClick={() => setCaseScreen("gate")} style={{ flex: 1 }}>Cancel</button>
                    <button className="btn btn-primary" onClick={createCase} disabled={caseLoading}
                      style={{ flex: 2 }}>
                      {caseLoading ? "Creating..." : "Create Case"}
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* Backend Status */}
            <div style={{ textAlign: "center", marginTop: 24 }}>
              <span style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                Backend: {backendUrl}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* ═══ MAIN APP — shown when case is active ═══ */}
      {caseActive && (
      <div className="app-container">
        {/* Header */}
        <header className="header">
          <div className="header-left">
            <div className="logo-mark"><Icons.Shield /></div>
            <div className="brand-text">
              <h1>SIGIL</h1>
              <p>DFIR Compromise Assessment Tool</p>
            </div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 10, position: "relative" }}>
            <span className="version-badge">v2.0.0 — Open Source</span>
            {/* Case management buttons */}
            <button className="btn btn-secondary case-btn" onClick={closeCase} style={{ fontSize: 11 }}>
              Close Case
            </button>
            <button className="backend-config-toggle" onClick={() => { setShowBackendConfig(!showBackendConfig); if (!showBackendConfig) checkBackend(); }}>
              <span className={`backend-dot ${backendStatus === "ok" ? "ok" : backendStatus === "error" ? "error" : "unknown"}`} />
              Backend
            </button>
            {showBackendConfig && (
              <div className="backend-popover" onClick={(e) => e.stopPropagation()}>
                <h4>EVTX Parser Backend</h4>
                <div className="backend-url-row">
                  <input
                    value={backendUrl}
                    onChange={(e) => setBackendUrl(e.target.value)}
                    placeholder="http://127.0.0.1:8001"
                  />
                  <button className="btn btn-primary" style={{ padding: "7px 12px", fontSize: 11 }} onClick={checkBackend}>Test</button>
                </div>
                <div className={`backend-status-msg ${backendStatus === "ok" ? "valid" : backendStatus === "error" ? "invalid" : ""}`} style={{ color: backendStatus === "ok" ? "var(--accent-green)" : backendStatus === "error" ? "var(--accent-red)" : "var(--text-muted)" }}>
                  {backendStatus === "ok" && "✓ Backend connected"}
                  {backendStatus === "error" && "✗ Cannot reach backend — parsing and detection unavailable"}
                  {backendStatus === null && "Click Test to check connection"}
                </div>
                <p style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 10, lineHeight: 1.5 }}>
                  The backend uses python-evtx to properly parse binary .evtx files into structured events. Start it with: <code style={{ color: "var(--accent-cyan)" }}>uvicorn main:app --port 8001</code>
                </p>
              </div>
            )}
          </div>
        </header>

        {/* Case Banner */}
        <div className="case-banner">
          <div className="case-banner-left">
            <Icons.Clipboard />
            <span className="case-name">{caseMeta.name}</span>
            {caseMeta.examiner && <span className="case-meta-item">Examiner: {caseMeta.examiner}</span>}
            {caseDir && <span className="case-meta-item" style={{ fontSize: 9, opacity: 0.6 }}>{caseDir}</span>}
          </div>
        </div>

        {/* Case Create/Edit Modal */}
        {showCaseModal && (
          <div className="modal-overlay" onClick={() => setShowCaseModal(false)}>
            <div className="modal-content" style={{ maxWidth: 500 }} onClick={(e) => e.stopPropagation()}>
              <div className="modal-header">
                <h3>{caseMeta.name ? "Edit Case" : "Create New Case"}</h3>
                <button className="modal-close" onClick={() => setShowCaseModal(false)}>×</button>
              </div>
              <div className="modal-body">
                <div className="form-group">
                  <label className="form-label">Case Name *</label>
                  <input className="form-input" value={caseMeta.name} onChange={(e) => setCaseMeta(prev => ({ ...prev, name: e.target.value }))} placeholder="e.g. Webserver Compromise Case" />
                </div>
                <div className="form-group">
                  <label className="form-label">Examiner</label>
                  <input className="form-input" value={caseMeta.examiner} onChange={(e) => setCaseMeta(prev => ({ ...prev, examiner: e.target.value }))} placeholder="e.g. Rodel" />
                </div>
                <div className="form-group">
                  <label className="form-label">Description</label>
                  <textarea className="form-textarea" value={caseMeta.description} onChange={(e) => setCaseMeta(prev => ({ ...prev, description: e.target.value }))} placeholder="Brief description of the investigation..." />
                </div>
              </div>
              <div className="modal-footer">
                <button className="btn btn-secondary" onClick={() => setShowCaseModal(false)}>Cancel</button>
                <button className="btn btn-primary" onClick={() => {
                  if (!caseMeta.createdAt) setCaseMeta(prev => ({ ...prev, createdAt: new Date().toISOString() }));
                  setShowCaseModal(false);
                }} disabled={!caseMeta.name.trim()}>
                  {caseMeta.createdAt ? "Save" : "Create Case"}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Tabs */}
        <div className="tab-bar">
          <button className={`tab-btn ${activeTab === "analyze" ? "active" : ""}`} onClick={() => setActiveTab("analyze")}>Analyze</button>
          <button className={`tab-btn ${activeTab === "lateral" ? "active" : ""}`} onClick={() => { setActiveTab("lateral"); if (!lateralMovement?.data) openLateralMovement(); }}>
            Lateral Movement
          </button>
          <button className={`tab-btn ${activeTab === "proctree" ? "active" : ""}`} onClick={() => { setActiveTab("proctree"); if (!processTree?.data) runProcessTree(); }}>
            Process Inspector
          </button>
          <button className={`tab-btn ${activeTab === "timeline" ? "active" : ""}`} onClick={() => setActiveTab("timeline")}>
            Timeline {findings.length > 0 ? `(${totalTimelineEvents()})` : ""}
          </button>
          <button className={`tab-btn ${activeTab === "rules" ? "active" : ""}`} onClick={() => setActiveTab("rules")}>Detection Rules ({allRules.length})</button>
        </div>

        {activeTab === "rules" && (
          <div>
            {/* Rule Actions Bar */}
            <div className="rule-actions-bar">
              <div style={{ display: "flex", gap: 8 }}>
                <button className="btn btn-primary" onClick={() => openNewRule("windows_event_log")}>+ New Rule</button>
                <button className="btn btn-secondary" onClick={resetRules}>Reset Defaults</button>
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                <button className="btn btn-secondary" onClick={exportRules}>
                  <Icons.Download /> Export Rules
                </button>
                <label className="btn btn-secondary" style={{ cursor: "pointer", marginBottom: 0 }}>
                  <Icons.Upload /> Import Rules
                  <input type="file" accept=".json" style={{ display: "none" }} onChange={importRulesFromFile} />
                </label>
                <label className="btn btn-secondary" style={{ cursor: "pointer", marginBottom: 0, color: "var(--accent-purple)" }}>
                  <Icons.Upload /> Import Sigma (.yml)
                  <input type="file" accept=".yml,.yaml" multiple style={{ display: "none" }} onChange={importSigmaRules} />
                </label>
              </div>
            </div>
            <div className="rule-browser">
              {allRules.map(rule => (
                <div key={rule.id}>
                  <div className="rule-item" onClick={() => setRuleExpanded(ruleExpanded === rule.id ? null : rule.id)}>
                    <div className="rule-item-left">
                      <span className="rule-id">{rule.id}</span>
                      <span className="severity-dot" style={{ background: `var(--severity-${rule.severity})` }} />
                      <span className="rule-name">{rule.name}</span>
                    </div>
                    <div className="rule-item-right">
                      <span className={`severity-badge badge-${rule.severity}`}>{rule.severity}</span>
                      <span style={{ fontSize: 11, color: logTypeColor(rule.logType), fontFamily: "var(--font-mono)" }}>{logTypeLabel(rule.logType)}</span>
                      <span className={`chevron-icon ${ruleExpanded === rule.id ? "open" : ""}`}><Icons.ChevronDown /></span>
                    </div>
                  </div>
                  {ruleExpanded === rule.id && (
                    <div style={{ padding: "0 20px 16px", borderBottom: "1px solid var(--border-primary)" }}>
                      <p style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.6, margin: "8px 0 12px" }}>{rule.description}</p>
                      <div className="mitre-tags" style={{ marginBottom: 10 }}>
                        {rule.mitre.map(t => {
                          const tech = MITRE_TECHNIQUES[t];
                          return tech ? (
                            <a key={t} href={tech.url} target="_blank" rel="noopener noreferrer" className="mitre-tag">
                              {tech.id}: {tech.name} <Icons.ExternalLink />
                            </a>
                          ) : <span key={t} className="mitre-tag">{t}</span>;
                        })}
                      </div>
                      <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)", marginBottom: 10 }}>
                        Keywords: {rule.keywords.join(", ")}
                      </div>
                      <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)", marginBottom: 12 }}>
                        Pattern: <span style={{ color: "var(--accent-cyan)" }}>{rule.pattern instanceof RegExp ? rule.pattern.source : String(rule.pattern)}</span>
                      </div>
                      {rule.sigmaSource && (
                        <div style={{ fontSize: 10, color: "var(--accent-purple)", fontFamily: "var(--font-mono)", marginBottom: 10, padding: "6px 10px", background: "#8b5cf610", borderRadius: 4, border: "1px solid #8b5cf620" }}>
                          Sigma: {rule.sigmaSource.filename}
                          {rule.sigmaSource.author && ` — by ${rule.sigmaSource.author}`}
                          {rule.sigmaSource.status && ` (${rule.sigmaSource.status})`}
                          {rule.sigmaSource.id && <span style={{ color: "var(--text-muted)", marginLeft: 8 }}>ID: {rule.sigmaSource.id}</span>}
                        </div>
                      )}
                      {/* Edit / Delete buttons */}
                      <div style={{ display: "flex", gap: 8 }}>
                        <button className="rule-action-btn-edit" onClick={(e) => { e.stopPropagation(); openEditRule(rule); }}>
                          ✎ Edit
                        </button>
                        <button className="rule-action-btn-del" onClick={(e) => { e.stopPropagation(); deleteRule(rule); }}>
                          <Icons.Trash /> Delete
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              ))}
              {allRules.length === 0 && (
                <div className="empty-state" style={{ padding: 40 }}>
                  <h3>No Detection Rules</h3>
                  <p>Create a new rule or reset to defaults.</p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Rule Editor Modal */}
        <RuleEditorModal />
        {/* Evidence Viewer Modal */}
        <EvidenceViewerModal />

        {/* Lateral Movement Tab */}
        {activeTab === "lateral" && (
          <div>
            {/* Config Phase — EventID Selector */}
            {lmPhase === "config" && (
              <div style={{ maxWidth: 950, margin: "0 auto", padding: 16 }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16 }}>
                  <div>
                    <h2 style={{ margin: 0, fontSize: 18 }}><Icons.Target /> Lateral Movement Tracker</h2>
                    <p style={{ margin: "4px 0 0", fontSize: 11, color: "var(--text-muted)" }}>
                      Select which Event IDs to search across your EVTX artifacts. Real detection comes from correlating patterns across multiple event types.
                    </p>
                  </div>
                  <div style={{ textAlign: "right" }}>
                    <div style={{ fontSize: 22, fontWeight: 700, color: "var(--accent-cyan)", fontFamily: "var(--font-mono)" }}>{lmSelectedEids.size}</div>
                    <div style={{ fontSize: 9, color: "var(--text-muted)", textTransform: "uppercase" }}>Event IDs Selected</div>
                  </div>
                </div>

                {/* EventID Category Grid */}
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 20 }}>
                  {LM_EVENT_CATEGORIES.map(cat => {
                    const allSelected = cat.eids.every(e => lmSelectedEids.has(e.id));
                    const someSelected = cat.eids.some(e => lmSelectedEids.has(e.id));
                    return (
                      <div key={cat.name} style={{ background: "var(--bg-card)", border: "1px solid var(--border-primary)", borderRadius: 8, overflow: "hidden" }}>
                        <div style={{ padding: "10px 14px", display: "flex", alignItems: "center", justifyContent: "space-between", borderBottom: "1px solid var(--border-primary)", background: someSelected ? "rgba(56,189,248,0.04)" : "transparent" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                            <span style={{ fontSize: 16 }}>{cat.icon}</span>
                            <div>
                              <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-primary)" }}>{cat.name}</div>
                              <div style={{ fontSize: 9, color: "var(--text-muted)" }}>{cat.desc}</div>
                            </div>
                          </div>
                          <button onClick={() => {
                            setLmSelectedEids(prev => {
                              const next = new Set(prev);
                              if (allSelected) { cat.eids.forEach(e => next.delete(e.id)); }
                              else { cat.eids.forEach(e => next.add(e.id)); }
                              return next;
                            });
                          }} style={{ fontSize: 9, padding: "3px 8px", background: allSelected ? "rgba(56,189,248,0.15)" : "var(--bg-primary)", border: "1px solid var(--border-primary)", borderRadius: 4, color: allSelected ? "var(--accent-cyan)" : "var(--text-muted)", cursor: "pointer", fontFamily: "var(--font-mono)" }}>
                            {allSelected ? "Deselect All" : "Select All"}
                          </button>
                        </div>
                        <div style={{ padding: "6px 10px" }}>
                          {cat.eids.map(eid => {
                            const isOn = lmSelectedEids.has(eid.id);
                            const sevColors = { critical: "var(--severity-critical)", high: "var(--severity-high)", medium: "var(--severity-medium)", low: "var(--severity-low)" };
                            return (
                              <label key={eid.id} style={{ display: "flex", alignItems: "center", gap: 8, padding: "5px 4px", cursor: "pointer", borderRadius: 4, background: isOn ? "rgba(56,189,248,0.04)" : "transparent" }}
                                onClick={() => setLmSelectedEids(prev => { const next = new Set(prev); isOn ? next.delete(eid.id) : next.add(eid.id); return next; })}>
                                <span style={{ width: 16, height: 16, borderRadius: 3, border: isOn ? "2px solid var(--accent-cyan)" : "2px solid var(--border-primary)", background: isOn ? "var(--accent-cyan)" : "transparent", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 10, color: "var(--bg-primary)", flexShrink: 0, transition: "all 0.15s" }}>
                                  {isOn ? "✓" : ""}
                                </span>
                                <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, fontWeight: 600, color: sevColors[eid.sev] || "var(--text-primary)", minWidth: 38 }}>{eid.id}</span>
                                <span style={{ fontSize: 11, color: "var(--text-secondary)", flex: 1 }}>{eid.label}</span>
                                <span style={{ fontSize: 9, color: "var(--text-muted)", fontStyle: "italic" }}>{eid.hint}</span>
                              </label>
                            );
                          })}
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Technique Mapping Table */}
                <div style={{ background: "var(--bg-card)", border: "1px solid var(--border-primary)", borderRadius: 8, padding: 16, marginBottom: 20 }}>
                  <h4 style={{ margin: "0 0 10px", fontSize: 12, color: "var(--accent-cyan)", fontFamily: "var(--font-mono)" }}>Lateral Movement Technique → Event ID Mapping</h4>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 6, fontSize: 11 }}>
                    {[
                      { tech: "PsExec", eids: "4624, 4648, 7045, 4688" },
                      { tech: "WMI", eids: "4624, 4688, 5861" },
                      { tech: "RDP", eids: "4624 (Type 10), 4778, 1149" },
                      { tech: "SMB / Admin Shares", eids: "4624 (Type 3), 5140, 5145" },
                      { tech: "Pass-the-Hash", eids: "4624, 4648, 4776" },
                      { tech: "Kerberoasting", eids: "4768, 4769" },
                    ].map(t => (
                      <div key={t.tech} style={{ padding: "6px 10px", background: "var(--bg-primary)", borderRadius: 4, border: "1px solid var(--border-primary)" }}>
                        <div style={{ fontWeight: 600, color: "var(--text-primary)", fontSize: 11 }}>{t.tech}</div>
                        <div style={{ fontFamily: "var(--font-mono)", color: "var(--accent-cyan)", fontSize: 10, marginTop: 2 }}>{t.eids}</div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Action Bar */}
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                    {artifacts.filter(a => a.logType === "windows_event_log").length} EVTX file(s) will be analyzed · {lmSelectedEids.size} Event IDs selected
                  </span>
                  <div style={{ display: "flex", gap: 8 }}>
                    <button className="btn btn-secondary" onClick={() => {
                      const all = new Set();
                      LM_EVENT_CATEGORIES.forEach(c => c.eids.forEach(e => all.add(e.id)));
                      setLmSelectedEids(all);
                    }} style={{ fontSize: 11 }}>Select All</button>
                    <button className="btn btn-secondary" onClick={() => setLmSelectedEids(new Set())} style={{ fontSize: 11 }}>Clear All</button>
                    <button className="btn btn-primary" onClick={runLateralMovement}
                      disabled={lmSelectedEids.size === 0 || artifacts.filter(a => a.logType === "windows_event_log").length === 0}
                      style={{ padding: "10px 28px", fontSize: 13 }}>
                      Analyze ({lmSelectedEids.size} Event IDs)
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* Loading Phase */}
            {lateralMovement?.loading && (
              <div style={{ padding: 80, textAlign: "center", display: "flex", flexDirection: "column", alignItems: "center" }}>
                <div className="parsing-spinner" />
                <p style={{ marginTop: 16, color: "var(--text-muted)", fontSize: 13 }}>Analyzing {lmSelectedEids.size} Event IDs across {artifacts.filter(a => a.logType === "windows_event_log").length} EVTX files...</p>
              </div>
            )}

            {lateralMovement?.error && (
              <div style={{ padding: 40, textAlign: "center" }}>
                <p style={{ color: "var(--accent-red)" }}>Error: {lateralMovement.error}</p>
                <button className="btn btn-secondary" onClick={() => setLmPhase("config")} style={{ marginTop: 12 }}>← Back to Config</button>
              </div>
            )}

            {/* Results Phase */}
            {lmPhase === "results" && lateralMovement?.data && (() => {
              const { data } = lateralMovement;
              const { summary, graph, logons, chains, findings: lmFindings } = data;

              if (summary.total_logons === 0) return (
                <div style={{ padding: 60, textAlign: "center" }}>
                  <p style={{ color: "var(--text-muted)", fontSize: 14 }}>No lateral movement events found matching the selected Event IDs.</p>
                  <button className="btn btn-secondary" onClick={() => setLmPhase("config")} style={{ marginTop: 12 }}>← Back to Config</button>
                </div>
              );

              return (
                <div>
                  {/* Summary Bar */}
                  <div style={{ display: "flex", gap: 14, padding: "14px 20px", borderBottom: "1px solid var(--border-primary)", flexWrap: "wrap", alignItems: "center" }}>
                    {[
                      { label: "Logons", value: summary.total_logons, color: "var(--accent-cyan)" },
                      { label: "Sources", value: summary.unique_sources, color: "var(--accent-blue)" },
                      { label: "Targets", value: summary.unique_targets, color: "var(--accent-green)" },
                      { label: "RDP", value: summary.rdp_logons, color: "var(--accent-red)" },
                      { label: "Failed", value: summary.failed_logons, color: "var(--accent-orange)" },
                      { label: "Chains", value: summary.chain_count, color: "var(--accent-purple)" },
                      { label: "Findings", value: (lmFindings || []).length, color: "var(--severity-critical)" },
                    ].map(s => (
                      <div key={s.label} style={{ textAlign: "center", minWidth: 60 }}>
                        <div style={{ fontSize: 20, fontWeight: 700, color: s.color, fontFamily: "var(--font-mono)" }}>{s.value}</div>
                        <div style={{ fontSize: 8, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 1 }}>{s.label}</div>
                      </div>
                    ))}
                    <button className="btn btn-secondary" onClick={() => setLmPhase("config")} style={{ marginLeft: "auto", fontSize: 10 }}>← Reconfigure</button>
                  </div>

                  {/* Sub-tabs */}
                  <div style={{ display: "flex", gap: 0, borderBottom: "1px solid var(--border-primary)" }}>
                    {[
                      { id: "graph", label: "Network Graph" },
                      { id: "timeline", label: `Timeline (${logons.length})` },
                      { id: "chains", label: `Chains (${chains.length})` },
                      { id: "findings", label: `Findings (${(lmFindings || []).length})` },
                    ].map(tab => (
                      <button key={tab.id} onClick={() => setLmTab(tab.id)}
                        style={{ padding: "10px 18px", background: "transparent", border: "none",
                          borderBottom: lmTab === tab.id ? "2px solid var(--accent-cyan)" : "2px solid transparent",
                          color: lmTab === tab.id ? "var(--accent-cyan)" : "var(--text-muted)",
                          cursor: "pointer", fontSize: 11, fontFamily: "var(--font-mono)", fontWeight: 600, textTransform: "uppercase", letterSpacing: 1 }}>
                        {tab.label}
                      </button>
                    ))}
                  </div>

                  <div style={{ padding: 16 }}>
                    {/* Network Graph */}
                    {lmTab === "graph" && (
                      <div>
                        <div style={{ background: "var(--bg-primary)", borderRadius: 8, border: "1px solid var(--border-primary)", minHeight: 450 }}>
                          <svg ref={lmSvgRef} viewBox="0 0 900 500" style={{ width: "100%", height: "auto", cursor: "default" }}
                            onMouseMove={(e) => {
                              if (!lmDragRef.current) return;
                              try {
                                const svg = lmSvgRef.current;
                                if (!svg) return;
                                const ctm = svg.getScreenCTM();
                                if (!ctm) return;
                                const pt = svg.createSVGPoint();
                                pt.x = e.clientX; pt.y = e.clientY;
                                const svgP = pt.matrixTransform(ctm.inverse());
                                setLmNodePositions(prev => ({ ...prev, [lmDragRef.current?.nodeId]: { x: svgP.x, y: svgP.y } }));
                              } catch (err) { /* ignore drag errors */ }
                            }}
                            onMouseUp={() => { lmDragRef.current = null; }}
                            onMouseLeave={() => { lmDragRef.current = null; }}>
                            <defs>
                              <marker id="lm-arrow" markerWidth="8" markerHeight="6" refX="24" refY="3" orient="auto">
                                <polygon points="0 0, 8 3, 0 6" fill="var(--text-muted)" opacity="0.6" />
                              </marker>
                            </defs>
                            {graph.edges.map((edge, i) => {
                              const sp = lmNodePositions[edge.source], tp = lmNodePositions[edge.target];
                              if (!sp || !tp) return null;
                              const isHL = lmSelectedNode && (edge.source === lmSelectedNode || edge.target === lmSelectedNode);
                              const isDim = lmSelectedNode && !isHL;
                              return (
                                <g key={i}>
                                  <line x1={sp.x} y1={sp.y} x2={tp.x} y2={tp.y}
                                    stroke={isHL ? "#38bdf8" : edge.color || "#6b7280"}
                                    strokeWidth={isHL ? 3 : Math.min(Math.max(edge.count * 0.5, 1), 4)}
                                    opacity={isDim ? 0.08 : isHL ? 1 : 0.5} markerEnd="url(#lm-arrow)" />
                                  {!isDim && <text x={(sp.x + tp.x) / 2} y={(sp.y + tp.y) / 2 - 6} textAnchor="middle" fill={isHL ? "#38bdf8" : "var(--text-muted)"} fontSize={8} fontFamily="monospace">{edge.count}×</text>}
                                </g>
                              );
                            })}
                            {graph.nodes.map((node) => {
                              const pos = lmNodePositions[node.id];
                              if (!pos) return null;
                              const isSel = lmSelectedNode === node.id;
                              const isConn = lmSelectedNode && graph.edges.some(e => (e.source === lmSelectedNode && e.target === node.id) || (e.target === lmSelectedNode && e.source === node.id));
                              const isDim = lmSelectedNode && !isSel && !isConn;
                              const isIp = node.type === "ip";
                              const fillColor = isSel ? "#38bdf8" : node.role === "source" ? "#3b82f6" : node.role === "target" ? "#10b981" : "#f59e0b";
                              return (
                                <g key={node.id} style={{ cursor: "grab" }} opacity={isDim ? 0.12 : 1}
                                  onMouseDown={(e) => { e.preventDefault(); lmDragRef.current = { nodeId: node.id }; }}
                                  onClick={(e) => { e.stopPropagation(); setLmSelectedNode(prev => prev === node.id ? null : node.id); }}>
                                  {isIp ? (
                                    <circle cx={pos.x} cy={pos.y} r={isSel ? 24 : 20} fill={fillColor} fillOpacity={0.15} stroke={fillColor} strokeWidth={isSel ? 3 : 2} strokeDasharray={isSel ? "none" : "4,2"} />
                                  ) : (
                                    <rect x={pos.x - (isSel ? 28 : 24)} y={pos.y - (isSel ? 18 : 16)} width={isSel ? 56 : 48} height={isSel ? 36 : 32} rx={6} fill={fillColor} fillOpacity={0.15} stroke={fillColor} strokeWidth={isSel ? 3 : 2} />
                                  )}
                                  {isSel && <circle cx={pos.x} cy={pos.y} r={32} fill="none" stroke="#38bdf8" strokeWidth={1} opacity={0.3} />}
                                  <text x={pos.x} y={pos.y + 4} textAnchor="middle" fill={isDim ? "var(--text-muted)" : "var(--text-primary)"} fontSize={9} fontFamily="monospace" fontWeight={isSel ? "700" : "600"} style={{ pointerEvents: "none" }}>
                                    {node.id.length > 16 ? node.id.slice(0, 15) + "\u2026" : node.id}
                                  </text>
                                </g>
                              );
                            })}
                          </svg>
                        </div>
                        <div style={{ display: "flex", gap: 16, marginTop: 10, fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--font-mono)", flexWrap: "wrap" }}>
                          <span><span style={{ color: "#3b82f6" }}>{"\u25CF"}</span> Source</span>
                          <span><span style={{ color: "#10b981" }}>{"\u25CF"}</span> Target</span>
                          <span><span style={{ color: "#f59e0b" }}>{"\u25CF"}</span> Both</span>
                          <span style={{ marginLeft: "auto" }}>Click node to highlight {"\u00B7"} Drag to move</span>
                        </div>
                      </div>
                    )}

                    {/* Timeline */}
                    {lmTab === "timeline" && (
                      <div style={{ overflowX: "auto" }}>
                        <table className="evidence-table">
                          <thead><tr>
                            <th style={{ width: 155 }}>Timestamp</th><th style={{ width: 45 }}>EID</th>
                            <th style={{ width: 130 }}>Source</th><th style={{ width: 15 }}>{"\u2192"}</th>
                            <th style={{ width: 130 }}>Target</th><th style={{ width: 110 }}>User</th>
                            <th style={{ width: 55 }}>Status</th><th>Logon Type</th>
                          </tr></thead>
                          <tbody>
                            {logons.slice(0, 500).map((l, i) => (
                              <tr key={i} style={{ background: l.status === "Failed" ? "rgba(239,68,68,0.06)" : "transparent" }}>
                                <td style={{ fontFamily: "var(--font-mono)", fontSize: 10 }}>{(l.timestamp || "").slice(0, 19)}</td>
                                <td style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--accent-cyan)" }}>{l.event_id}</td>
                                <td style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--accent-blue)" }}>{l.source}</td>
                                <td style={{ textAlign: "center", color: "var(--text-muted)" }}>{"\u2192"}</td>
                                <td style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--accent-green)" }}>{l.target}</td>
                                <td style={{ fontFamily: "var(--font-mono)", fontSize: 10 }}>{l.target_user}</td>
                                <td style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: l.status === "Failed" ? "var(--accent-red)" : "var(--accent-green)", fontWeight: 600 }}>{l.status}</td>
                                <td style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: l.logon_type_color }}>{l.logon_type_label}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                        {logons.length > 500 && <p style={{ textAlign: "center", color: "var(--text-muted)", fontSize: 11, marginTop: 8 }}>Showing 500 of {logons.length} events</p>}
                      </div>
                    )}

                    {/* Chains */}
                    {lmTab === "chains" && (
                      <div>
                        {chains.length === 0 ? (
                          <div style={{ padding: 40, textAlign: "center", color: "var(--text-muted)" }}>No multi-hop lateral movement chains detected.</div>
                        ) : chains.map((chain, ci) => (
                          <div key={ci} style={{ background: "var(--bg-card)", border: "1px solid var(--border-primary)", borderRadius: 8, padding: 16, marginBottom: 12 }}>
                            <div style={{ fontSize: 12, fontWeight: 600, color: "var(--accent-cyan)", marginBottom: 8, fontFamily: "var(--font-mono)" }}>Chain #{ci + 1} {"\u2014"} {chain.length} hops</div>
                            <div style={{ display: "flex", alignItems: "center", gap: 4, flexWrap: "wrap" }}>
                              {chain.map((hop, hi) => (
                                <Fragment key={hi}>
                                  {hi === 0 && <span style={{ padding: "4px 10px", background: "rgba(59,130,246,0.15)", border: "1px solid var(--accent-blue)", borderRadius: 6, fontSize: 11, fontFamily: "var(--font-mono)", color: "var(--accent-blue)" }}>{hop.source}</span>}
                                  <span style={{ color: "var(--text-muted)", fontSize: 16 }}>{"\u2192"}</span>
                                  <div style={{ textAlign: "center" }}>
                                    <span style={{ padding: "4px 10px", background: "rgba(16,185,129,0.15)", border: "1px solid var(--accent-green)", borderRadius: 6, fontSize: 11, fontFamily: "var(--font-mono)", color: "var(--accent-green)", display: "inline-block" }}>{hop.target}</span>
                                    <div style={{ fontSize: 8, color: "var(--text-muted)", fontFamily: "var(--font-mono)", marginTop: 2 }}>{hop.target_user} {"\u00B7"} {hop.logon_type_label}</div>
                                  </div>
                                </Fragment>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}

                    {/* Findings */}
                    {lmTab === "findings" && (
                      <div>
                        {(!lmFindings || lmFindings.length === 0) ? (
                          <div style={{ padding: 40, textAlign: "center", color: "var(--text-muted)" }}>No suspicious patterns detected.</div>
                        ) : lmFindings.map((f, fi) => {
                          const sevColors = { critical: "var(--severity-critical)", high: "var(--severity-high)", medium: "var(--severity-medium)", low: "var(--severity-low)" };
                          return (
                            <div key={fi} style={{ background: "var(--bg-card)", border: "1px solid var(--border-primary)", borderRadius: 8, padding: 16, marginBottom: 10, borderLeft: `3px solid ${sevColors[f.severity] || "var(--text-muted)"}` }}>
                              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                                <span style={{ fontSize: 10, fontWeight: 700, color: sevColors[f.severity], textTransform: "uppercase", fontFamily: "var(--font-mono)", padding: "2px 8px", background: `${sevColors[f.severity]}22`, borderRadius: 4 }}>{f.severity}</span>
                                {f.mitre && <span style={{ fontSize: 10, fontFamily: "var(--font-mono)", color: "var(--accent-cyan)", padding: "2px 6px", background: "rgba(56,189,248,0.1)", borderRadius: 4 }}>{f.mitre}</span>}
                                <span style={{ fontSize: 12, fontWeight: 600 }}>{f.title}</span>
                              </div>
                              <p style={{ fontSize: 11, color: "var(--text-secondary)", margin: 0, fontFamily: "var(--font-mono)", lineHeight: 1.5 }}>{f.desc}</p>
                              {f.source && (
                                <button onClick={() => { setLmSelectedNode(f.source); setLmTab("graph"); }}
                                  style={{ marginTop: 8, fontSize: 10, color: "var(--accent-cyan)", background: "none", border: "1px solid var(--accent-cyan)", borderRadius: 4, padding: "3px 10px", cursor: "pointer", fontFamily: "var(--font-mono)" }}>
                                  View in Graph
                                </button>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>
                </div>
              );
            })()}
          </div>
        )}

        {/* Process Inspector Tab */}
        {activeTab === "proctree" && (
          <div>
            {processTree?.loading && (
              <div style={{ padding: 80, textAlign: "center", display: "flex", flexDirection: "column", alignItems: "center" }}>
                <div className="parsing-spinner" />
                <p style={{ marginTop: 16, color: "var(--text-muted)", fontSize: 13 }}>Building process tree from Sysmon EID 1 and Security EID 4688...</p>
              </div>
            )}

            {processTree?.error && (
              <div style={{ padding: 40, textAlign: "center" }}>
                <p style={{ color: "var(--accent-red)" }}>Error: {processTree.error}</p>
                <button className="btn btn-secondary" onClick={runProcessTree} style={{ marginTop: 12 }}>Retry</button>
              </div>
            )}

            {processTree?.data && (() => {
              const { tree, findings: ptFindings, summary } = processTree.data;

              if (summary.total_processes === 0) return (
                <div style={{ padding: 60, textAlign: "center" }}>
                  <p style={{ color: "var(--text-muted)", fontSize: 14 }}>No process creation events found (Sysmon EID 1 or Security EID 4688).</p>
                  <p style={{ color: "var(--text-muted)", fontSize: 11, marginTop: 8 }}>Upload EVTX files containing process creation logs to use the Process Inspector.</p>
                </div>
              );

              const sevColors = { critical: "var(--severity-critical)", high: "var(--severity-high)", medium: "var(--severity-medium)", low: "var(--severity-low)" };

              // Filter tree
              const searchLower = ptSearch.toLowerCase();
              const filteredTree = tree.filter(n => {
                if (ptSevFilter !== "all") {
                  if (ptSevFilter === "detections" && !n.has_detection) return false;
                  if (ptSevFilter !== "detections" && !n.detections?.some(d => d.severity === ptSevFilter)) return false;
                }
                if (searchLower && !(
                  (n.name || "").toLowerCase().includes(searchLower) ||
                  (n.cmd_line || "").toLowerCase().includes(searchLower) ||
                  (n.user || "").toLowerCase().includes(searchLower)
                )) return false;
                return true;
              });

              return (
                <div>
                  {/* Summary */}
                  <div style={{ display: "flex", gap: 14, padding: "14px 20px", borderBottom: "1px solid var(--border-primary)", flexWrap: "wrap", alignItems: "center" }}>
                    {[
                      { label: "Processes", value: summary.total_processes, color: "var(--accent-cyan)" },
                      { label: "Sysmon", value: summary.sysmon_events, color: "var(--accent-blue)" },
                      { label: "Security", value: summary.security_events, color: "var(--accent-green)" },
                      { label: "Findings", value: summary.total_findings, color: "var(--severity-high)" },
                      { label: "Critical", value: summary.critical_count, color: "var(--severity-critical)" },
                      { label: "High", value: summary.high_count, color: "var(--severity-high)" },
                    ].map(s => (
                      <div key={s.label} style={{ textAlign: "center", minWidth: 55 }}>
                        <div style={{ fontSize: 18, fontWeight: 700, color: s.color, fontFamily: "var(--font-mono)" }}>{s.value}</div>
                        <div style={{ fontSize: 8, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 1 }}>{s.label}</div>
                      </div>
                    ))}
                    <button className="btn btn-secondary" onClick={runProcessTree} style={{ marginLeft: "auto", fontSize: 10 }}>Refresh</button>
                  </div>

                  {/* Filters */}
                  <div style={{ display: "flex", gap: 8, padding: "10px 16px", borderBottom: "1px solid var(--border-primary)", alignItems: "center", flexWrap: "wrap" }}>
                    <input type="text" value={ptSearch} onChange={e => setPtSearch(e.target.value)}
                      placeholder="Search process name, command line, user..."
                      style={{ flex: 1, minWidth: 200, padding: "6px 10px", background: "var(--bg-primary)", border: "1px solid var(--border-primary)", borderRadius: 6, color: "var(--text-primary)", fontSize: 12 }} />
                    {["all", "detections", "critical", "high", "medium"].map(f => (
                      <button key={f} className={`filter-chip ${ptSevFilter === f ? "active" : ""}`}
                        onClick={() => setPtSevFilter(f)}
                        style={{ fontSize: 10 }}>
                        {f === "all" ? "All" : f === "detections" ? `Detections (${summary.total_findings})` : f.charAt(0).toUpperCase() + f.slice(1)}
                      </button>
                    ))}
                  </div>

                  {/* Process Tree */}
                  <div style={{ padding: 16, maxHeight: "calc(100vh - 350px)", overflowY: "auto" }}>
                    {filteredTree.length === 0 ? (
                      <div style={{ padding: 40, textAlign: "center", color: "var(--text-muted)" }}>No matching processes found.</div>
                    ) : filteredTree.slice(0, 500).map((node, i) => {
                      const indent = Math.min(node.depth, 10) * 20;
                      const hasDetection = node.has_detection;
                      const maxSev = hasDetection ? node.detections.reduce((m, d) => {
                        const order = { critical: 0, high: 1, medium: 2, low: 3 };
                        return order[d.severity] < order[m] ? d.severity : m;
                      }, "low") : null;

                      return (
                        <div key={node.key || i} style={{
                          marginLeft: indent,
                          padding: "6px 12px", marginBottom: 2,
                          background: hasDetection ? `${sevColors[maxSev]}08` : "transparent",
                          borderLeft: hasDetection ? `3px solid ${sevColors[maxSev]}` : "3px solid transparent",
                          borderRadius: 4,
                          fontSize: 11,
                        }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                            {/* Tree connector */}
                            {node.depth > 0 && (
                              <span style={{ color: "var(--text-muted)", fontSize: 10 }}>└─</span>
                            )}
                            {/* Process name */}
                            <span style={{ fontFamily: "var(--font-mono)", fontWeight: 600, color: hasDetection ? sevColors[maxSev] : "var(--accent-cyan)", fontSize: 12 }}>
                              {node.name || "unknown"}
                            </span>
                            {/* PID */}
                            <span style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-muted)" }}>
                              PID:{node.pid}
                            </span>
                            {/* User */}
                            {node.user && (
                              <span style={{ fontSize: 9, color: "var(--text-muted)" }}>{node.user}</span>
                            )}
                            {/* Integrity */}
                            {node.integrity && (
                              <span style={{
                                fontSize: 8, padding: "1px 5px", borderRadius: 3,
                                background: node.integrity === "System" ? "#ef444420" : node.integrity === "High" ? "#f59e0b20" : "#6b728020",
                                color: node.integrity === "System" ? "#ef4444" : node.integrity === "High" ? "#f59e0b" : "var(--text-muted)",
                                fontFamily: "var(--font-mono)",
                              }}>{node.integrity}</span>
                            )}
                            {/* Timestamp */}
                            <span style={{ fontSize: 9, color: "var(--text-muted)", marginLeft: "auto", fontFamily: "var(--font-mono)" }}>
                              {(node.timestamp || "").slice(0, 19)}
                            </span>
                          </div>

                          {/* Command line */}
                          {node.cmd_line && (
                            <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-secondary)", marginTop: 3, marginLeft: node.depth > 0 ? 24 : 0, wordBreak: "break-all", lineHeight: 1.4 }}>
                              {node.cmd_line.length > 200 ? node.cmd_line.slice(0, 200) + "…" : node.cmd_line}
                            </div>
                          )}

                          {/* Detection badges */}
                          {hasDetection && node.detections.map((det, di) => (
                            <div key={di} style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 4, marginLeft: node.depth > 0 ? 24 : 0 }}>
                              <span style={{ fontSize: 9, fontWeight: 700, color: sevColors[det.severity], textTransform: "uppercase", fontFamily: "var(--font-mono)", padding: "1px 6px", background: `${sevColors[det.severity]}15`, borderRadius: 3 }}>
                                {det.severity}
                              </span>
                              <span style={{ fontSize: 9, color: "var(--accent-cyan)", fontFamily: "var(--font-mono)" }}>
                                {det.mitre?.join(", ")}
                              </span>
                              <span style={{ fontSize: 10, color: "var(--text-secondary)" }}>
                                {det.rule_name}
                              </span>
                            </div>
                          ))}
                        </div>
                      );
                    })}
                    {filteredTree.length > 500 && (
                      <p style={{ textAlign: "center", color: "var(--text-muted)", fontSize: 11, marginTop: 12 }}>
                        Showing 500 of {filteredTree.length} processes
                      </p>
                    )}
                  </div>
                </div>
              );
            })()}
          </div>
        )}

        {/* Timeline Tab */}
        {activeTab === "timeline" && (
          <div>
            {findings.length === 0 ? (
              <div className="empty-state">
                <h3>No Findings Yet</h3>
                <p>Run a threat hunt in the Analyze tab first. The timeline will show matched events sorted chronologically.</p>
              </div>
            ) : (() => {
              const allTimelineEvents = buildTimeline();
              const filteredTimeline = timelineSevFilter === "all"
                ? allTimelineEvents
                : allTimelineEvents.filter(ev => ev.severity === timelineSevFilter);
              const totalEvents = filteredTimeline.length;
              const totalPages = Math.max(1, Math.ceil(totalEvents / TIMELINE_PAGE_SIZE));
              const currentPage = Math.min(timelinePage, totalPages - 1);
              const pageStart = currentPage * TIMELINE_PAGE_SIZE;
              const pageEnd = Math.min(pageStart + TIMELINE_PAGE_SIZE, totalEvents);
              const pageEvents = filteredTimeline.slice(pageStart, pageEnd);
              // Group current page by date
              const groups = {};
              for (const ev of pageEvents) {
                const dateKey = ev.timestamp ? ev.timestamp.slice(0, 10) : "Unknown Date";
                if (!groups[dateKey]) groups[dateKey] = [];
                groups[dateKey].push(ev);
              }
              // Compute page range for display
              const maxPageButtons = 7;
              let pageRangeStart = Math.max(0, currentPage - Math.floor(maxPageButtons / 2));
              let pageRangeEnd = Math.min(totalPages, pageRangeStart + maxPageButtons);
              if (pageRangeEnd - pageRangeStart < maxPageButtons) pageRangeStart = Math.max(0, pageRangeEnd - maxPageButtons);

              // Severity counts for filter chips
              const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 };
              for (const ev of allTimelineEvents) sevCounts[ev.severity] = (sevCounts[ev.severity] || 0) + 1;

              return (
                <div>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12, flexWrap: "wrap", gap: 8 }}>
                    <h2 style={{ fontSize: 16, fontWeight: 700, display: "flex", alignItems: "center", gap: 8 }}>
                      <Icons.Search /> Event Timeline
                    </h2>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" }}>
                      {totalEvents} events{timelineSevFilter !== "all" ? ` (${timelineSevFilter})` : ""} — showing {totalEvents > 0 ? `${pageStart + 1}–${pageEnd}` : "0"} (page {currentPage + 1}/{totalPages})
                    </span>
                  </div>

                  {/* Severity filter bar */}
                  <div className="filter-bar" style={{ marginBottom: 12 }}>
                    <span style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>Filter:</span>
                    {["all", "critical", "high", "medium", "low"].map(f => (
                      sevCounts[f] > 0 || f === "all" ? (
                        <button key={f} className={`filter-chip ${timelineSevFilter === f ? "active" : ""}`} onClick={() => { setTimelineSevFilter(f); setTimelinePage(0); }}>
                          {f === "all" ? `All (${allTimelineEvents.length})` : `${f.charAt(0).toUpperCase() + f.slice(1)} (${sevCounts[f] || 0})`}
                        </button>
                      ) : null
                    ))}
                  </div>

                  {/* Top pagination */}
                  {totalPages > 1 && (
                    <div className="timeline-pagination">
                      <button disabled={currentPage === 0} onClick={() => setTimelinePage(0)}>«</button>
                      <button disabled={currentPage === 0} onClick={() => setTimelinePage(currentPage - 1)}>‹</button>
                      {pageRangeStart > 0 && <span className="page-info">…</span>}
                      {Array.from({ length: pageRangeEnd - pageRangeStart }, (_, i) => pageRangeStart + i).map(p => (
                        <button key={p} className={p === currentPage ? "active" : ""} onClick={() => setTimelinePage(p)}>
                          {p + 1}
                        </button>
                      ))}
                      {pageRangeEnd < totalPages && <span className="page-info">…</span>}
                      <button disabled={currentPage >= totalPages - 1} onClick={() => setTimelinePage(currentPage + 1)}>›</button>
                      <button disabled={currentPage >= totalPages - 1} onClick={() => setTimelinePage(totalPages - 1)}>»</button>
                    </div>
                  )}

                  <div className="timeline-container">
                    <div className="timeline-line" />
                    {Object.entries(groups).map(([date, evts]) => (
                      <div key={date}>
                        <div className="timeline-group-header">{date}</div>
                        {evts.map((ev, idx) => (
                          <div
                            key={`${ev.findingId}-${idx}`}
                            className="timeline-event"
                            onClick={() => {
                              const singleEventFinding = {
                                ...ev.finding,
                                matchedEvents: ev.event ? [ev.event] : [],
                                _timelineClick: true
                              };
                              openEvidenceViewer(singleEventFinding);
                            }}
                          >
                            <div className="timeline-dot" style={{ background: `var(--severity-${ev.severity})`, boxShadow: `0 0 6px var(--severity-${ev.severity})` }} />
                            <div className="timeline-time">
                              {ev.timestamp ? ev.timestamp.slice(11, 23) : "—"}
                            </div>
                            <span className={`severity-badge badge-${ev.severity}`} style={{ flexShrink: 0 }}>{ev.severity}</span>
                            <div className="timeline-finding-name">{ev.findingName}</div>
                            {ev.eventId && <div className="timeline-event-id">EID: {ev.eventId}</div>}
                            {ev.recordId && <div className="timeline-record-id">RID: {ev.recordId}</div>}
                          </div>
                        ))}
                      </div>
                    ))}
                  </div>

                  {/* Bottom pagination */}
                  {totalPages > 1 && (
                    <div className="timeline-pagination">
                      <button disabled={currentPage === 0} onClick={() => { setTimelinePage(0); window.scrollTo(0, 0); }}>«</button>
                      <button disabled={currentPage === 0} onClick={() => { setTimelinePage(currentPage - 1); window.scrollTo(0, 0); }}>‹</button>
                      {pageRangeStart > 0 && <span className="page-info">…</span>}
                      {Array.from({ length: pageRangeEnd - pageRangeStart }, (_, i) => pageRangeStart + i).map(p => (
                        <button key={p} className={p === currentPage ? "active" : ""} onClick={() => { setTimelinePage(p); window.scrollTo(0, 0); }}>
                          {p + 1}
                        </button>
                      ))}
                      {pageRangeEnd < totalPages && <span className="page-info">…</span>}
                      <button disabled={currentPage >= totalPages - 1} onClick={() => { setTimelinePage(currentPage + 1); window.scrollTo(0, 0); }}>›</button>
                      <button disabled={currentPage >= totalPages - 1} onClick={() => { setTimelinePage(totalPages - 1); window.scrollTo(0, 0); }}>»</button>
                      <span className="page-info">Page {currentPage + 1} of {totalPages}</span>
                    </div>
                  )}
                </div>
              );
            })()}
          </div>
        )}

        {activeTab === "analyze" && (
          <div>
            {/* Upload Zone */}
            <div
              className={`upload-zone ${dragover ? "dragover" : ""}`}
              onDragOver={(e) => { e.preventDefault(); setDragover(true); }}
              onDragLeave={() => setDragover(false)}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
            >
              <input
                ref={fileInputRef}
                type="file"
                multiple
                accept=".log,.txt,.evtx,.csv,.json,.xml,.reg"
                style={{ display: "none" }}
                onChange={(e) => handleFiles(e.target.files)}
              />
              <div className="upload-icon"><Icons.Upload /></div>
              <div className="upload-text">
                <h3>Drop artifacts here or click to browse</h3>
                <p>Windows Event Logs, Web Server Logs (IIS/Apache/Nginx), Registry Exports</p>
              </div>
              <div className="supported-types">
                {[".log", ".txt", ".evtx", ".csv", ".json", ".xml", ".reg"].map(t => (
                  <span key={t} className="type-badge">{t}</span>
                ))}
              </div>
              <div className="paste-area" onClick={(e) => e.stopPropagation()}>
                <button className="paste-toggle" onClick={() => setShowPaste(!showPaste)}>
                  {showPaste ? "▾ Hide paste input" : "▸ Or paste log content directly"}
                </button>
                {showPaste && (
                  <div>
                    <textarea
                      className="paste-input"
                      placeholder="Paste raw log content here..."
                      value={pasteContent}
                      onChange={(e) => setPasteContent(e.target.value)}
                      onClick={(e) => e.stopPropagation()}
                    />
                    <div className="paste-actions">
                      <button className="btn btn-secondary" onClick={() => { setPasteContent(""); setShowPaste(false); }}>Cancel</button>
                      <button className="btn btn-primary" onClick={handlePasteSubmit} disabled={!pasteContent.trim()}>Ingest Log</button>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Loaded Artifacts Panel */}
            {artifacts.length > 0 && (
              <div className="artifacts-panel">
                <div className="artifacts-header" onClick={() => setFilesExpanded(!filesExpanded)}>
                  <div className="artifacts-header-left">
                    <span className="artifacts-count">{artifacts.length}</span>
                    <span className="artifacts-header-title">
                      Loaded Artifact{artifacts.length !== 1 ? "s" : ""}
                    </span>
                    <div className="artifacts-summary">
                      {(() => {
                        const types = {};
                        artifacts.forEach(a => {
                          const t = a.logType || "unknown";
                          types[t] = (types[t] || 0) + 1;
                        });
                        return Object.entries(types).map(([t, count]) => (
                          <span key={t} style={{ display: "flex", alignItems: "center", gap: 4 }}>
                            <span className="artifacts-summary-dot" style={{ background: logTypeColor(t) }} />
                            {count} {logTypeLabel(t)}
                          </span>
                        ));
                      })()}
                      <span style={{ color: "var(--text-muted)" }}>
                        ({(artifacts.reduce((s, a) => s + (a.size || a.hashes?.file_size || 0), 0) / 1024).toFixed(1)} KB total)
                      </span>
                    </div>
                  </div>
                  <div className="artifacts-header-right">
                    <button className="artifacts-clear-btn" onClick={(e) => { e.stopPropagation(); setArtifacts([]); setFilesExpanded(false); }}>
                      Clear All
                    </button>
                    <span className={`chevron-icon ${filesExpanded ? "open" : ""}`}><Icons.ChevronDown /></span>
                  </div>
                </div>
                {filesExpanded && (
                  <div className="artifacts-body">
                    <div className="loaded-files">
                      {artifacts.map((a, i) => (
                        <div key={i} className="file-chip">
                          <span className="type-indicator" style={{ background: logTypeColor(a.logType) }} />
                          <Icons.File />
                          <span>{a.name}</span>
                          <span style={{ color: "var(--text-muted)", fontSize: 10 }}>
                            {a.logType ? logTypeLabel(a.logType) : "Unknown"}
                          </span>
                          <span style={{ color: "var(--text-muted)", fontSize: 10 }}>
                            {((a.size || a.hashes?.file_size || 0) / 1024).toFixed(1)}KB
                          </span>
                          {a.parsedBackend && (
                            <span className="parsed-badge backend">
                              {a.eventCount} events{a.webLogFormat ? ` · ${a.webLogFormat}` : ""}
                            </span>
                          )}
                          {a.fallback && (
                            <span className="parsed-badge fallback">fallback</span>
                          )}
                          <button onClick={() => removeArtifact(i)} title="Remove"><Icons.Trash /></button>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* EVTX Parsing Progress */}
            {parsingFiles > 0 && (
              <div className="parsing-banner">
                <div className="parsing-spinner" />
                <span>Parsing {parsingFiles} file{parsingFiles !== 1 ? "s" : ""}.</span>
              </div>
            )}

            {/* IOC Panel */}
            <div className="ioc-panel">
              <div className="ioc-header" onClick={() => setShowIocPanel(!showIocPanel)}>
                <div className="ioc-header-left">
                  <Icons.Target />
                  <span style={{ fontSize: 13, fontWeight: 600 }}>IOC Hunting</span>
                  {iocList.length > 0 && <span className="ioc-count">{iocList.length}</span>}
                  {iocList.length > 0 && (
                    <span style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                      {iocList.filter(i => i.type === "ip").length} IPs · {iocList.filter(i => i.type === "domain").length} domains
                    </span>
                  )}
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  {iocList.length > 0 && (
                    <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 11, color: "var(--text-muted)" }} onClick={(e) => e.stopPropagation()}>
                      <span>{iocEnabled ? "On" : "Off"}</span>
                      <div className={`ioc-toggle ${iocEnabled ? "active" : ""}`} onClick={() => setIocEnabled(!iocEnabled)} />
                    </div>
                  )}
                  <span className={`chevron-icon ${showIocPanel ? "open" : ""}`}><Icons.ChevronDown /></span>
                </div>
              </div>
              {showIocPanel && (
                <div className="ioc-body">
                  <div className="ioc-input-row">
                    <input
                      value={iocInput}
                      onChange={(e) => setIocInput(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") { addIocs(iocInput); setIocInput(""); }
                      }}
                      placeholder="Enter IPs or domains (comma/newline separated)..."
                    />
                    <button className="btn btn-primary" style={{ fontSize: 11, padding: "6px 12px", whiteSpace: "nowrap" }} onClick={() => { addIocs(iocInput); setIocInput(""); }} disabled={!iocInput.trim()}>
                      Add
                    </button>
                    <label className="btn btn-secondary" style={{ fontSize: 11, padding: "6px 12px", cursor: "pointer", marginBottom: 0, whiteSpace: "nowrap", display: "inline-flex", alignItems: "center", boxSizing: "border-box" }}>
                      Import File
                      <input ref={iocFileRef} type="file" accept=".txt,.csv,.ioc,.tsv" style={{ display: "none" }} onChange={importIocFile} />
                    </label>
                    {iocList.length > 0 && (
                      <button className="btn btn-danger" style={{ fontSize: 11, padding: "6px 12px", whiteSpace: "nowrap" }} onClick={clearIocs}>
                        Clear All
                      </button>
                    )}
                  </div>
                  <div className="form-hint" style={{ marginBottom: 10 }}>
                    Paste IPs and domains, one per line or comma-separated. Import from .txt/.csv files. URLs are auto-stripped to domains.
                  </div>
                  {iocList.length > 0 && (
                    <div className="ioc-tags">
                      {iocList.map((ioc, i) => (
                        <span key={i} className={`ioc-tag ${ioc.type}`}>
                          {ioc.type === "ip" ? "IP" : "DNS"}: {ioc.value}
                          <button onClick={() => removeIoc(ioc.value)}>×</button>
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Analysis Controls */}
            <div className="analysis-controls">
              <button
                className="run-btn"
                onClick={runAnalysis}
                disabled={artifacts.length === 0 || scanning || parsingFiles > 0}
              >
                <Icons.Search /> Run Threat Hunt
                {iocEnabled && iocList.length > 0 && (
                  <span style={{ fontSize: 10, opacity: 0.8, marginLeft: 4 }}>+ {iocList.length} IOCs</span>
                )}
              </button>
              {findings.length > 0 && (
                <div className="filter-bar">
                  <span style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>Filter:</span>
                  {["all", "critical", "high", "medium", "low"].map(f => (
                    <button key={f} className={`filter-chip ${severityFilter === f ? "active" : ""}`} onClick={() => setSeverityFilter(f)}>
                      {f === "all" ? "All" : f.charAt(0).toUpperCase() + f.slice(1)}
                      {f !== "all" && ` (${findings.filter(x => x.severity === f).length})`}
                    </button>
                  ))}
                  <div style={{ marginLeft: "auto", position: "relative" }}>
                    <button className="btn btn-primary" style={{ fontSize: 11, padding: "5px 14px", display: "inline-flex", alignItems: "center", gap: 6 }}
                      onClick={() => setShowReportMenu(!showReportMenu)}>
                      <Icons.File /> Generate Report ▾
                    </button>
                    {showReportMenu && (
                      <div style={{
                        position: "absolute", right: 0, top: "100%", marginTop: 4, zIndex: 100,
                        background: "var(--bg-card)", border: "1px solid var(--border-primary)",
                        borderRadius: "var(--radius-lg)", boxShadow: "0 8px 24px rgba(0,0,0,0.4)",
                        minWidth: 220, overflow: "hidden"
                      }}>
                        {[
                          { mode: "all", label: "All Findings", desc: `${findings.length} findings` },
                          { mode: "bookmarked", label: "★ Bookmarked Only", desc: `${totalBookmarkedEvents} bookmarked` },
                          { mode: "critical-high", label: "Critical & High", desc: `${findings.filter(f => f.severity === "critical" || f.severity === "high").length} findings` },
                          { mode: "critical", label: "Critical Only", desc: `${findings.filter(f => f.severity === "critical").length} findings` },
                        ].map(opt => (
                          <button key={opt.mode}
                            style={{
                              display: "block", width: "100%", padding: "10px 16px", border: "none",
                              background: "transparent", color: "var(--text-primary)", textAlign: "left",
                              cursor: "pointer", fontSize: 12, fontFamily: "var(--font-mono)",
                              borderBottom: "1px solid var(--border-primary)",
                            }}
                            onMouseEnter={(e) => e.currentTarget.style.background = "var(--bg-card-hover)"}
                            onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}
                            onClick={() => { setShowReportMenu(false); generateReport(opt.mode); }}>
                            <div style={{ fontWeight: 600 }}>{opt.label}</div>
                            <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 2 }}>{opt.desc}</div>
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>

            {/* Scanning Animation */}
            {scanning && (
              <div className="scanning-overlay">
                <div className="scanning-content">
                  <div className="scan-ring" />
                  <h3>Hunting for threats...</h3>
                  <p>Running {Object.values(customRules).flat().length} detection rules against {artifacts.length} artifact{artifacts.length !== 1 ? "s" : ""}</p>
                </div>
              </div>
            )}

            {/* Results */}
            {overallScore && (
              <div>
                {/* Score Banner */}
                <div className={`score-banner ${overallScore.label.toLowerCase()}`}>
                  <div style={{ display: "flex", alignItems: "center", gap: 20, paddingLeft: 24 }}>
                    <div className="pulse" />
                    <div>
                      <div className="score-label" style={{ color: overallScore.color }}>{overallScore.label}</div>
                      <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 2 }}>Overall Assessment</div>
                    </div>
                  </div>
                  <div className="score-details">
                    <p><span className="count">{findings.length}</span> finding{findings.length !== 1 ? "s" : ""} detected</p>
                    <p style={{ fontSize: 11, marginTop: 2 }}>Threat Score: <span className="count">{overallScore.score}</span></p>
                  </div>
                </div>

                {/* Stats */}
                <div className="stats-grid">
                  <div className="stat-card">
                    <div className="stat-value" style={{ color: "var(--severity-critical)" }}>
                      {findings.filter(f => f.severity === "critical").length}
                    </div>
                    <div className="stat-label">Critical</div>
                  </div>
                  <div className="stat-card">
                    <div className="stat-value" style={{ color: "var(--severity-high)" }}>
                      {findings.filter(f => f.severity === "high").length}
                    </div>
                    <div className="stat-label">High</div>
                  </div>
                  <div className="stat-card">
                    <div className="stat-value" style={{ color: "var(--severity-medium)" }}>
                      {findings.filter(f => f.severity === "medium").length}
                    </div>
                    <div className="stat-label">Medium</div>
                  </div>
                  <div className="stat-card">
                    <div className="stat-value" style={{ color: "var(--text-secondary)" }}>
                      {artifacts.length}
                    </div>
                    <div className="stat-label">Artifacts</div>
                  </div>
                  <div className="stat-card">
                    <div className="stat-value" style={{ color: "var(--accent-purple)" }}>
                      {[...new Set(findings.flatMap(f => f.mitre))].length}
                    </div>
                    <div className="stat-label">MITRE Techniques</div>
                  </div>
                </div>

                {/* Findings */}
                <div className="findings-section">
                  <h2><Icons.AlertTriangle /> Findings
                    {totalBookmarkedEvents > 0 && (
                      <span style={{ fontSize: 11, fontWeight: 400, color: "var(--accent-orange)", marginLeft: 8 }}>
                        ★ {totalBookmarkedEvents} bookmarked
                      </span>
                    )}
                  </h2>
                  {filteredFindings.length === 0 && (
                    <div className="empty-state" style={{ padding: 40 }}>
                      <p>No findings match the current filter.</p>
                    </div>
                  )}
                  {filteredFindings.map(f => {
                    const isOpen = expandedFindings.has(f.uid || f.id);
                    return (
                      <div key={f.uid || f.id} className="finding-card">
                        <div className="finding-header" onClick={() => toggleFinding(f.uid || f.id)}>
                          <div className="finding-header-left">
                            <span className={`severity-dot severity-${f.severity}`} />
                            <span className="finding-title">{f.name}</span>
                            <span style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>{f.id}</span>
                          </div>
                          <div className="finding-header-right">
                            {getBookmarkedCountForFinding(f.uid || f.id) > 0 && (
                              <span style={{ fontSize: 11, color: "var(--accent-orange)", fontFamily: "var(--font-mono)", fontWeight: 600 }}>
                                ★ {getBookmarkedCountForFinding(f.uid || f.id)}
                              </span>
                            )}
                            <div className="confidence-meter">
                              <div className="confidence-bar-bg">
                                <div className="confidence-bar-fill" style={{ width: `${f.confidence}%`, background: getConfidenceColor(f.confidence) }} />
                              </div>
                              {f.confidence}%
                            </div>
                            <span className={`severity-badge badge-${f.severity}`}>{f.severity}</span>
                            <span className={`chevron-icon ${isOpen ? "open" : ""}`}><Icons.ChevronDown /></span>
                          </div>
                        </div>
                        {isOpen && (
                          <div className="finding-body">
                            <p className="finding-description">{f.description}</p>
                            <div className="detail-grid">
                              <div className="detail-box">
                                <h4><Icons.Target /> MITRE ATT&CK</h4>
                                <div className="mitre-tags">
                                  {f.mitre.map(t => {
                                    const tech = MITRE_TECHNIQUES[t];
                                    return tech ? (
                                      <a key={t} href={tech.url} target="_blank" rel="noopener noreferrer" className="mitre-tag">
                                        {tech.id}: {tech.name} <Icons.ExternalLink />
                                      </a>
                                    ) : <span key={t} className="mitre-tag">{t}</span>;
                                  })}
                                </div>
                                {f.mitre.map(t => MITRE_TECHNIQUES[t]).filter(Boolean).map(tech => (
                                  <div key={tech.id} style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 6 }}>
                                    Tactic: {tech.tactic}
                                  </div>
                                ))}
                              </div>
                              <div className="detail-box">
                                <h4><Icons.Search /> Detection Details</h4>
                                <div className="match-info">
                                  Pattern matches: <span>{f.matchCount}</span><br />
                                  Keyword hits: <span>{f.keywordHits}</span><br />
                                  Source: <span>{f.source}</span><br />
                                  Type: <span style={{ color: logTypeColor(f.logType) }}>{logTypeLabel(f.logType)}</span>
                                </div>
                                {f.excerpts?.length > 0 && (
                                  <div className="excerpts" style={{ marginTop: 10 }}>
                                    <div style={{ fontSize: 10, color: "var(--text-muted)", marginBottom: 4 }}>Matched excerpts:</div>
                                    {f.excerpts.map((ex, i) => (
                                      <span key={i} className="excerpt">{ex.length > 80 ? ex.slice(0, 80) + "…" : ex}</span>
                                    ))}
                                  </div>
                                )}
                              </div>
                            </div>
                            <div className="detail-box">
                              <h4><Icons.Info /> Suggested Next Steps</h4>
                              <ul className="next-steps">
                                {f.nextSteps.map((step, i) => <li key={i}>{step}</li>)}
                              </ul>
                            </div>
                            {/* Evidence Viewer Button */}
                            <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
                              <button
                                className="btn btn-primary"
                                onClick={() => openEvidenceViewer(f)}
                                style={{ fontSize: 12 }}
                              >
                                <Icons.Search /> View Evidence ({(f.matchedEvents || []).length} events)
                              </button>
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>

                {/* Export & Tools */}
                <div className="export-bar">
                  <button className="btn btn-secondary" onClick={exportJSON}>
                    <Icons.Download /> Export JSON
                  </button>
                  <button className="btn btn-secondary" onClick={exportMarkdown}>
                    <Icons.Download /> Export Markdown
                  </button>
                </div>
              </div>
            )}

            {/* Empty state */}
            {!overallScore && !scanning && findings.length === 0 && artifacts.length === 0 && (
              <div className="empty-state">
                <h3>No Artifacts Loaded</h3>
                <p>Upload Windows Event Logs (.evtx, .log, .txt), web server access logs (IIS, Apache, Nginx), or Registry exports (.reg) to begin threat hunting.</p>
              </div>
            )}
          </div>
        )}
      </div>
      )}
    </div>
  );
}