#!/bin/bash
# ==============================================================================
# UBUNTU SECURITY RECON & FORENSIC DASHBOARD - FULL EDITION
# Targeted for Competition Environments, Service Auditing, and Self-Healing
# ==============================================================================

# --- Global Variables & Setup ---
LOG_DIR="/tmp/recon_results"
mkdir -p "$LOG_DIR"
BASELINE_HASH="/tmp/config_baseline.hash"
DRIFT_LOG="$LOG_DIR/drift_report.txt"

# --- Internal Module: Malware Indicator Scan ---
run_malware_detect() {
    OUT="$LOG_DIR/malware_indicators.txt"
    echo "--- Forensic Threat Scan ($(date)) ---" > "$OUT"
    echo -e "\n[!] Unauthorized ptrace (Process Injection):" >> "$OUT"
    grep -r "ptrace" /proc/*/stack 2>/dev/null | grep -v "self" >> "$OUT"
    echo -e "\n[!] Active Reverse Shells (/dev/tcp):" >> "$OUT"
    lsof -i -P -n | grep -E "bash|sh|python|perl|php|ruby" | grep "ESTABLISHED" >> "$OUT"
    echo -e "\n[!] Suspicious Binary Strings (execve/sigsetmask):" >> "$OUT"
    find /tmp /dev/shm -type f -exec strings {} + 2>/dev/null | grep -E "execve|sigsetmask" >> "$OUT"
    whiptail --title "Malware Indicators" --textbox "$OUT" 20 90
}

# --- Internal Module: Credential & Log Audit ---
run_cred_audit() {
    AUDIT_LOG="$LOG_DIR/cred_audit.txt"
    echo "--- Credential & Service Log Audit ---" > "$AUDIT_LOG"
    echo -e "\n[!] HTTP/SQL/SSH Auth Failures:" >> "$AUDIT_LOG"
    grep -iE "401|403|access denied|password authentication failed" \
    /var/log/apache2/access.log /var/log/nginx/access.log \
    /var/log/mysql/error.log /var/log/auth.log 2>/dev/null | tail -n 25 >> "$AUDIT_LOG"
    whiptail --title "Credential Audit" --textbox "$AUDIT_LOG" 20 90
}

# --- Main Dashboard UI ---
while true; do
    CHOICE=$(whiptail --title "Ubuntu Security Recon Dashboard" \
    --menu "Select an operation (Current User: $USER):" 22 75 14 \
    "1" "Network Audit (Fixed Listeners/ESTAB)" \
    "2" "Persistence Check (Cron & Timers)" \
    "3" "Integrity Scan (Binaries & Config Files)" \
    "4" "Log Analysis (Sudo & History)" \
    "5" "Find Hidden Services/Processes" \
    "6" "Scan Logs for Attackers (Bruteforce)" \
    "7" "Manage Bans (IPTables/Fail2Ban)" \
    "8" "Check Services Health (Systemd)" \
    "9" "Forensic Malware Scan (ptrace/injection)" \
    "10" "Credential Audit (Service Logs)" \
    "11" "Generate Competition Wordlist" \
    "12" "Scan & Purge File Drift (Last 30m)" \
    "13" "Exit" 3>&1 1>&2 2>&3)

    case $CHOICE in
        1) clear; ./audit_network.sh || echo "Error: audit_network.sh not found." ;;
        2) clear; ./audit_persistence.sh ||
