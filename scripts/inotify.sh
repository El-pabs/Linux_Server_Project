#!/bin/bash

echo "Installation de inotify-tools..."
sudo dnf install -y inotify-tools

echo "Création du script de surveillance..."

cat << 'EOF' | sudo tee /usr/local/bin/inotify_monitor.sh > /dev/null
#!/bin/bash
LOGFILE="/var/log/inotify_monitor.log"
WATCHED_DIRS="/etc /var/www"

inotifywait -m -r -e modify,create,delete,move ${WATCHED_DIRS} --format '%T %w %f %e' --timefmt '%F %T' |
while read date time dir file event; do
    echo "[$date $time] Event: $event on $dir$file" >> "$LOGFILE"
done
EOF

sudo chmod +x /usr/local/bin/inotify_monitor.sh

echo "Création d'un service systemd pour lancer la surveillance au démarrage..."

cat << 'EOF' | sudo tee /etc/systemd/system/inotify-monitor.service > /dev/null
[Unit]
Description=Inotify File Monitoring Service
After=network.target

[Service]
ExecStart=/usr/local/bin/inotify_monitor.sh
Restart=always

[Install]
WantedBy=multi-user.target
EOF

echo "Activation et démarrage du service de surveillance..."
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable --now inotify-monitor.service

echo "Surveillance des fichiers système activée. Les événements sont enregistrés dans /var/log/inotify_monitor.log"
