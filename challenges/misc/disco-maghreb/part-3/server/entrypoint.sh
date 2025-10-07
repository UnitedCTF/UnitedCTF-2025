#!/bin/bash
set -euo pipefail

USER="boualem"
USER_HOME="/home/$USER"
SSH_DIR="$USER_HOME/.ssh"
APP_DIR="/app"

mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"
chown "$USER:$USER" "$SSH_DIR"

echo "Génération de la clé RSA-2048 pour $USER..."
sudo -u "$USER" ssh-keygen -t rsa -b 2048 -f "$SSH_DIR/id_rsa" -N "" -q
chown "$USER:$USER" "$SSH_DIR/id_rsa" "$SSH_DIR/id_rsa.pub"
chmod 600 "$SSH_DIR/id_rsa"
chmod 644 "$SSH_DIR/id_rsa.pub"

PUBKEY_CONTENT="$(cat "$SSH_DIR/id_rsa.pub")"
echo "$PUBKEY_CONTENT" > "$SSH_DIR/authorized_keys"
chmod 600 "$SSH_DIR/authorized_keys"
chown "$USER:$USER" "$SSH_DIR/authorized_keys"

/usr/sbin/sshd

echo "* * * * * /usr/local/bin/python3 /app/health-check-disco-maghreb.py >> /var/log/health-check-disco-maghreb.log 2>&1" > /etc/cron.d/health-check-disco-maghreb
chmod 0644 /etc/cron.d/health-check-disco-maghreb
crontab /etc/cron.d/health-check-disco-maghreb
cron

chown -R "$USER:$USER" "$APP_DIR"

exec sudo -u "$USER" python3 "$APP_DIR/server.py"
