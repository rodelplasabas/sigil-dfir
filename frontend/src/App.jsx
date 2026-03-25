import { useState, useCallback, useRef, useEffect } from "react";

// ═══════════════════════════════════════════════════════════════════════════════
// DFIR COMPROMISE ASSESSMENT TOOL — "SIGIL"
// Open-source triage assistant for incident responders
// ═══════════════════════════════════════════════════════════════════════════════

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
  const [parsingEvtx, setParsingEvtx] = useState(0);
  const [backendUrl, setBackendUrl] = useState("http://127.0.0.1:8001");
  const [showBackendConfig, setShowBackendConfig] = useState(false);
  const [backendStatus, setBackendStatus] = useState(null);
  const [evidenceViewer, setEvidenceViewer] = useState(null);
  const [caseMeta, setCaseMeta] = useState({ name: "", examiner: "", description: "", createdAt: null });
  const [showCaseModal, setShowCaseModal] = useState(false);
  const [caseModalMode, setCaseModalMode] = useState("create"); // "create" | "save"
  const [iocList, setIocList] = useState([]); // [{ value, type: "ip"|"domain" }]
  const [iocEnabled, setIocEnabled] = useState(true);
  const [showIocPanel, setShowIocPanel] = useState(false);
  const [iocInput, setIocInput] = useState("");
  const caseImportRef = useRef(null);
  const iocFileRef = useRef(null);
  const fileInputRef = useRef(null);

  // Parse EVTX via backend API
  // ── File Upload via Backend /parse ─────────────────────────────────
  const parseViaBackend = useCallback(async (file) => {
    setParsingEvtx(prev => prev + 1);
    try {
      const formData = new FormData();
      formData.append("file", file);
      const res = await fetch(`${backendUrl}/parse`, { method: "POST", body: formData });
      const data = await res.json();
      if (data.status === "success" && data.events) {
        setArtifacts(prev => [...prev, {
          name: file.name,
          size: file.size,
          file,
          content: data.events.map(e => e.content || e.message || "").join("\n"),
          logType: data.log_type || "unknown",
          timestamp: Date.now(),
          parsedBackend: true,
          eventCount: data.event_count,
          events: data.events,
          webLogFormat: data.format || "Unknown",
          hashes: data.hashes || null
        }]);
        setBackendStatus("ok");
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
      setParsingEvtx(prev => prev - 1);
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

  const generateReport = useCallback(async () => {
    try {
      const payload = {
        case_meta: caseMeta,
        findings: findings.map(f => ({
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
          matched_events: (f.matchedEvents || []).slice(0, 10).map(e => ({
            record_id: e.recordId || e.record_id || "",
            event_id: e.eventId || e.event_id || "",
            timestamp: e.timestamp || "",
            content: (e.content || e.message || "").slice(0, 200),
          })),
        })),
        overall_score: overallScore,
        artifacts: artifacts.map(a => ({
          name: a.name, log_type: a.logType, event_count: a.eventCount || 0,
          hashes: a.hashes || null
        })),
        ioc_list: iocList,
      };

      const res = await fetch(`${backendUrl}/report`, {
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
  }, [findings, overallScore, artifacts, caseMeta, iocList, backendUrl]);

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
      const results = await Promise.all(
        artifacts.filter(a => a.logType && a.logType !== "unknown").map(async (artifact) => {
          try {
            if (!artifact.file) return null;
            const formData = new FormData();
            formData.append("file", artifact.file);
            if (iocPayload) formData.append("ioc_list", iocPayload);
            formData.append("ioc_enabled", String(iocEnabled));
            const res = await fetch(`${backendUrl}/analyze`, { method: "POST", body: formData });
            const data = await res.json();
            if (data.status === "success" && data.findings) {
              return data.findings.map(f => ({
                id: f.id,
                name: f.name,
                description: f.description,
                severity: f.severity,
                mitre: f.mitre || [],
                matchCount: f.match_count,
                keywordHits: f.keyword_hits,
                confidence: f.confidence,
                excerpts: f.excerpts || [],
                matchedEvents: (f.matched_events || []).map(e => ({
                  timestamp: e.timestamp,
                  eventId: e.event_id,
                  recordId: e.record_id,
                  content: e.content,
                  message: e.message,
                  structuredFields: e.fields,
                  line_index: e.line_index
                })),
                nextSteps: f.next_steps || [],
                isIocRule: f.is_ioc_rule || false,
                source: artifact.name,
                logType: artifact.logType
              }));
            }
          } catch (err) {
            console.warn("Backend analyze failed for", artifact.name, err);
          }
          return null;
        })
      );

      for (const result of results) {
        if (result) allFindings.push(...result);
      }
    } catch (err) {
      console.error("Analysis failed:", err);
    }

    // Deduplicate by rule ID, merge matchedEvents
    const deduped = {};
    for (const f of allFindings) {
      const key = f.id;
      if (!deduped[key] || f.confidence > deduped[key].confidence) {
        if (deduped[key] && deduped[key].matchedEvents) {
          f.matchedEvents = [...(f.matchedEvents || []), ...deduped[key].matchedEvents];
        }
        deduped[key] = f;
      } else if (deduped[key]) {
        deduped[key].matchedEvents = [...(deduped[key].matchedEvents || []), ...(f.matchedEvents || [])];
      }
    }
    const final = Object.values(deduped).sort((a, b) => severityWeight(b.severity) - severityWeight(a.severity) || b.confidence - a.confidence);
    setFindings(final);
    setOverallScore(computeOverallScore(final));
    setScanning(false);
    if (final.length > 0) setExpandedFindings(new Set([final[0].id]));
  }, [artifacts, iocEnabled, iocList, backendUrl]);

  const toggleFinding = (id) => {
    setExpandedFindings(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

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
    artifacts.forEach(a => { md += `- **${a.name}** — ${logTypeLabel(a.logType)} (${(a.size/1024).toFixed(1)} KB)\n`; });
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
      iocEnabled: iocEnabled
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
          if (data.findings.length > 0) setExpandedFindings(new Set([data.findings[0].id]));
        }
        if (data.overallScore) setOverallScore(data.overallScore);
        if (data.iocList) setIocList(data.iocList);
        if (data.iocEnabled !== undefined) setIocEnabled(data.iocEnabled);
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
  const EvidenceViewerModal = () => {
    const [expandedRows, setExpandedRows] = useState(new Set());
    const [searchFilter, setSearchFilter] = useState("");

    if (!evidenceViewer) return null;
    const { finding } = evidenceViewer;
    const events = finding.matchedEvents || [];
    
    const filtered = searchFilter.trim()
      ? events.filter(e => {
          const s = searchFilter.toLowerCase();
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
      setExpandedRows(prev => {
        const next = new Set(prev);
        next.has(idx) ? next.delete(idx) : next.add(idx);
        return next;
      });
    };

    const highlightContent = (text, maxLen = 200) => {
      if (!text) return "";
      const display = expandedRows.has("full") ? text : text.slice(0, maxLen);
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
              const fullFinding = findings.find(f => f.id === finding.id);
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
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
            />
          </div>
          <div style={{ overflowY: "auto", maxHeight: "calc(90vh - 200px)" }}>
            {filtered.length === 0 ? (
              <div className="empty-state" style={{ padding: 40 }}>
                <p>{events.length === 0 ? "No event-level evidence captured for this finding." : "No events match your filter."}</p>
              </div>
            ) : (
              <table className="evidence-table">
                <thead>
                  <tr>
                    <th style={{ width: 40 }}>#</th>
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
                    const isExpanded = expandedRows.has(idx);
                    const contentText = ev.content || ev.message || "";
                    const fields = ev.structuredFields || ev.fields || null;
                    const isWeb = finding.logType === "web_server_log";

                    return (
                      <tr key={idx} className={`severity-row-${finding.severity}`}>
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
                              {highlightContent(contentText, isExpanded ? 99999 : 200)}
                              {contentText.length > 200 && (
                                <button className="evidence-expand-btn" onClick={() => toggleRow(idx)}>
                                  {isExpanded ? "▲ Collapse" : "▼ Show more"}
                                </button>
                              )}
                              {isExpanded && fields && Object.keys(fields).length > 0 && (
                                <div className="evidence-fields">
                                  {Object.entries(fields).map(([k, v]) => (
                                    <div key={k}>
                                      <span className="field-name">{k}:</span>
                                      <span className="field-value">{v && v.length > 300 ? v.slice(0, 300) + "…" : v}</span>
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
            <span className="version-badge">v1.0.0 — Open Source</span>
            {/* Case management buttons */}
            <button className="btn btn-secondary case-btn" onClick={() => { setCaseModalMode("create"); setShowCaseModal(true); }}>
              + New Case
            </button>
            <button className="btn btn-secondary case-btn" onClick={saveCase} disabled={!hasActiveCase && artifacts.length === 0 && findings.length === 0}>
              <Icons.Download /> Save
            </button>
            <label className="btn btn-secondary case-btn" style={{ cursor: "pointer", marginBottom: 0 }}>
              <Icons.Upload /> Open Case
              <input ref={caseImportRef} type="file" accept=".json" style={{ display: "none" }} onChange={importCase} />
            </label>
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
                  {backendStatus === "error" && "✗ Cannot reach backend — EVTX files will use text fallback"}
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
        {hasActiveCase && (
          <div className="case-banner">
            <div className="case-banner-left">
              <Icons.Clipboard />
              <span className="case-name">{caseMeta.name}</span>
              {caseMeta.examiner && <span className="case-meta-item">Examiner: {caseMeta.examiner}</span>}
              {caseMeta.createdAt && <span className="case-meta-item">Created: {caseMeta.createdAt.slice(0, 10)}</span>}
            </div>
            <div className="case-actions">
              <button className="btn btn-ghost" style={{ fontSize: 11 }} onClick={() => { setCaseModalMode("create"); setShowCaseModal(true); }}>
                Edit
              </button>
            </div>
          </div>
        )}

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
                  <input className="form-input" value={caseMeta.examiner} onChange={(e) => setCaseMeta(prev => ({ ...prev, examiner: e.target.value }))} placeholder="e.g. Examiner" />
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
                              setEvidenceViewer({ finding: singleEventFinding });
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
                        ({(artifacts.reduce((s, a) => s + a.size, 0) / 1024).toFixed(1)} KB total)
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
                            {(a.size / 1024).toFixed(1)}KB
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
            {parsingEvtx > 0 && (
              <div className="parsing-banner">
                <div className="parsing-spinner" />
                <span>Parsing {parsingEvtx} EVTX file{parsingEvtx !== 1 ? "s" : ""} via backend...</span>
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
                disabled={artifacts.length === 0 || scanning || parsingEvtx > 0}
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
                  <button className="btn btn-primary" style={{ marginLeft: "auto", fontSize: 11, padding: "5px 14px", display: "inline-flex", alignItems: "center", gap: 6 }} onClick={generateReport}>
                    <Icons.File /> Generate Report
                  </button>
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
                  <h2><Icons.AlertTriangle /> Findings</h2>
                  {filteredFindings.length === 0 && (
                    <div className="empty-state" style={{ padding: 40 }}>
                      <p>No findings match the current filter.</p>
                    </div>
                  )}
                  {filteredFindings.map(f => {
                    const isOpen = expandedFindings.has(f.id);
                    return (
                      <div key={f.id} className="finding-card">
                        <div className="finding-header" onClick={() => toggleFinding(f.id)}>
                          <div className="finding-header-left">
                            <span className={`severity-dot severity-${f.severity}`} />
                            <span className="finding-title">{f.name}</span>
                            <span style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>{f.id}</span>
                          </div>
                          <div className="finding-header-right">
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
                                onClick={() => setEvidenceViewer({ finding: f })}
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

                {/* Export */}
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
    </div>
  );
}