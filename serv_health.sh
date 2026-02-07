#!/bin/bash
# check_services.sh - Version/Status Detection

# Define service maps: [Generic Name]="DebianName FedoraName"
declare -A SVC_MAP=(
    ["SSH"]="sshd sshd"
    ["HTTP/S"]="nginx nginx"
    ["FTP"]="proftpd proftpd"
    ["LDAP"]="slapd dirsrv"
    ["DNS"]="bind9 named"
    ["SMB"]="smbd smb"
    ["Kerberos"]="krb5-kdc krb5kdc"
    ["POP3"]="dovecot dovecot"
)

echo "--- SERVICE STATUS & VERSIONS ---"

for FRIENDLY in "${!SVC_MAP[@]}"; do
    # Pick the right service name for the current OS
    read -r DEB_NAME FED_NAME <<< "${SVC_MAP[$FRIENDLY]}"
    
    if systemctl list-units --type=service | grep -q "$DEB_NAME"; then
        SVC=$DEB_NAME
    else
        SVC=$FED_NAME
    fi

    if systemctl is-active --quiet "$SVC"; then
        VERSION=$($SVC -v 2>&1 | head -n 1 || $SVC --version 2>&1 | head -n 1)
        echo "[OK] $FRIENDLY ($SVC) is running. Version: ${VERSION:-Unknown}"
    else
        echo "[OFFLINE] $FRIENDLY ($SVC) is not active."
    fi
done
