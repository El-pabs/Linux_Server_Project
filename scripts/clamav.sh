#!/bin/bash

echo "Installation et mise à jour de ClamAV..."
sudo dnf update -y
sudo dnf install -y clamav clamav-update

echo "Mise à jour de la base de signatures..."
if ! systemctl is-active --quiet clamav-freshclam; then
    sudo freshclam
fi

echo "Création du dossier de log ClamAV..."
sudo mkdir -p /var/log/clamav

echo "Configuration du scan automatique quotidien ciblé..."
SCAN_CMD="clamscan -r /var/www /home /mnt/raid5_share --exclude-dir=^/proc --exclude-dir=^/sys --exclude-dir=^/dev --infected --quiet --log=/var/log/clamav/daily_scan.log"
if ! grep -q "$SCAN_CMD" /etc/crontab; then
    echo "0 2 * * * root $SCAN_CMD" | sudo tee -a /etc/crontab > /dev/null
else
    echo "Tâche cron déjà existante."
fi

echo "Activation uniquement de la mise à jour automatique..."
sudo systemctl enable --now clamav-freshclam

echo "ClamAV est configuré pour des scans quotidiens ciblés sans démon actif."
