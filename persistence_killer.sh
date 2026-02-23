#!/bin/bash

# Ensure the script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root."
   exit 1
fi

LOG_FILE="/var/log/cron_security_audit.log"
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")

echo "--- Security Audit Started: $TIMESTAMP ---" | tee -a "$LOG_FILE"

# 1. Identify suspicious cron jobs (looking for useradd, usermod, or sudoers edits)
SUSPICIOUS_CRONS=$(grep -rE "useradd|usermod|visudo|NOPASSWD" /etc/cron* /var/spool/cron/crontabs 2>/dev/null)

if [ -z "$SUSPICIOUS_CRONS" ]; then
    echo "No immediate suspicious cron patterns detected." | tee -a "$LOG_FILE"
else
    echo "Suspicious Cron Jobs Found:" | tee -a "$LOG_FILE"
    echo "$SUSPICIOUS_CRONS" | tee -a "$LOG_FILE"

    # Extract filenames/paths from the grep results
    FILES_TO_REOVE=$(echo "$SUSPICIOUS_CRONS" | cut -d: -f1 | sort -u)

    for FILE in $FILES_TO_REOVE; do
        # Extract keywords to find linked processes
        # This assumes the cron points to a specific script or binary
        mapfile -t TRIGGERED_APPS < <(grep -E "useradd|usermod" "$FILE" | awk '{print $NF}')

        for APP in "${TRIGGERED_APPS[@]}"; do
            if [ -f "$APP" ] || [ -x "$(command -v "$APP")" ]; then
                APP_NAME=$(basename "$APP")
                
                # 2. Terminate active processes tied to the software
                echo "Terminating processes related to: $APP_NAME" | tee -a "$LOG_FILE"
                pkill -9 -f "$APP_NAME"

                # 3. Identify and drop active network connections (Web Apps/Reverse Shells)
                # We look for established connections tied to the PIDs of that app
                echo "Dropping network connections for $APP_NAME..." | tee -a "$LOG_FILE"
                lsof -i -n -P | grep "$APP_NAME" | awk '{print $2}' | xargs -r kill -9
            fi
        done

        # 4. Remove the malicious cron file/entry
        echo "Removing malicious cron file: $FILE" | tee -a "$LOG_FILE"
        rm -f "$FILE"
    done
fi

# 5. Final System Sanity Check
echo "Checking for unauthorized users with UID 0..." | tee -a "$LOG_FILE"
awk -F: '($3 == "0") {print $1}' /etc/passwd | grep -v "root" | tee -a "$LOG_FILE"

echo "--- Audit Complete ---" | tee -a "$LOG_FILE"
