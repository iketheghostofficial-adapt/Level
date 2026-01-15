#!/bin/bash
# Logic: Scans logs, identifies attackers with >= 3 failures, and bans them via iptables.

LOG_FILE="/var/log/fail2ban.log"
THRESHOLD=3
WHITELIST="/etc/proc_whitelist.txt" # Ensure your Jumpbox IP is in here!
CHAIN="BAD-ACTORS"

# 1. Ensure the BAD-ACTORS chain exists in iptables
sudo iptables -N $CHAIN 2>/dev/null
sudo iptables -C INPUT -j $CHAIN 2>/dev/null || sudo iptables -I INPUT 1 -j $CHAIN

echo "[*] Scanning $LOG_FILE for brute force attempts (Threshold: $THRESHOLD)..."

# 2. Extract IPs with 3 or more Failed password attempts
# We use a temp file to store the list of IPs that hit the threshold
ATTACKERS=$(grep "Ban" "$LOG_FILE" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | \
            sort | uniq -c | awk -v limit="$THRESHOLD" '$1 >= limit {print $2}')

if [ -z "$ATTACKERS" ]; then
    echo "[+] No brute force attempts detected."
    exit 0
fi

echo "--- [ACTION] Processing Ban List ---"

for IP in $ATTACKERS; do
    # Check if IP is already banned to avoid duplicate rules
    if sudo iptables -L $CHAIN -n | grep -q "$IP"; then
        echo "[i] $IP is already in the Deny List."
        continue
    fi

    # Check against the Whitelist
    if grep -q "$IP" "$WHITELIST" 2>/dev/null; then
        echo "[!] SKIPPING: $IP is a whitelisted management IP."
    else
        # 3. Add to the ACL Deny List (The Ban Action)
        echo -e "\033[0;31m[!] BANNING: $IP (Exceeded $THRESHOLD failed attempts)\033[0m"
        sudo iptables -A $CHAIN -s "$IP" -j DROP
        
        # Log the action for audit purposes
        echo "$(date): Banned $IP after 3 failed SSH attempts" >> /var/log/active_bans.log
    fi
done

echo "[*] Current Active Bans in $CHAIN:"
sudo iptables -L $CHAIN -n --line-numbers
