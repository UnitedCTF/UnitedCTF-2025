#!/bin/bash

echo "==================================="
echo "  Setting up Horloger Suisse CTF  "
echo "==================================="

# Create necessary directories
mkdir -p /var/log/horloger
mkdir -p /tmp/horloger

# Set up log directory permissions
chown www-data:www-data /var/log/horloger
chmod 755 /var/log/horloger

# Create hint files for privilege escalation discovery
echo "# Swiss Horloger System Administration Notes" > /opt/horloger/system_notes.txt
echo "# Time management is critical for precise Swiss clockwork" >> /opt/horloger/system_notes.txt

chown www-data:www-data /opt/horloger/system_notes.txt
chmod 644 /opt/horloger/system_notes.txt

# Create a cronjob hint
echo "# Swiss Horloger Maintenance Tasks" > /etc/cron.d/horloger
echo "# */5 * * * * root /usr/local/bin/timedatectl status > /var/log/horloger/time_check.log" >> /etc/cron.d/horloger
echo "# Precision timing maintenance - Swiss quality guaranteed" >> /etc/cron.d/horloger

# Set permissions for discovery
chmod 644 /etc/cron.d/horloger

# Make sure our custom timedatectl is in PATH and findable
ln -sf /usr/local/bin/timedatectl /usr/bin/timedatectl

echo "Swiss precision setup complete!"