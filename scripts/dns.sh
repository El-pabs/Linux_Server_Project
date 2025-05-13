#!/bin/bash
set -e

# ==========================================
# Script de déploiement Tout-en-Un
# Usage: sudo ./deploy.sh [full|user] NOM_CLIENT DOMAINE
# ==========================================

WEB_ROOT="/var/www"
DNS_ZONE_DIR="/var/named"
DNS_CONF="/etc/named.conf"
LOG_FILE="/var/log/deploy.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

fix_firewall() {
    # Ouvre les ports nécessaires si firewalld est actif
    if systemctl is-active --quiet firewalld; then
        log "Configuration du firewall local (firewalld)"
        sudo firewall-cmd --permanent --add-service=http
        sudo firewall-cmd --permanent --add-service=https
        sudo firewall-cmd --permanent --add-service=ftp
        sudo firewall-cmd --permanent --add-port=53/tcp
        sudo firewall-cmd --permanent --add-port=53/udp
        sudo firewall-cmd --permanent --add-port=30000-31000/tcp
        sudo firewall-cmd --reload
    fi
}

fix_resolv_conf() {
    # Ajoute le DNS local dans resolv.conf pour la résolution locale
    if ! grep -q "^nameserver 127.0.0.1" /etc/resolv.conf; then
        log "Ajout de nameserver 127.0.0.1 dans /etc/resolv.conf"
        sudo sed -i '1inameserver 127.0.0.1' /etc/resolv.conf
    fi
}

fix_apache_servername() {
    # Ajoute ServerName localhost si absent pour éviter le warning
    if ! grep -q "^ServerName" /etc/httpd/conf/httpd.conf; then
        echo "ServerName localhost" | sudo tee -a /etc/httpd/conf/httpd.conf
    fi
}

configure_dns() {
    DOMAIN=$1
    IP=$(curl -s ifconfig.me)
    ZONE_FILE="$DNS_ZONE_DIR/$DOMAIN.db"

    log "Configuration DNS pour $DOMAIN"

    # Création fichier de zone si absent
    if [ ! -f "$ZONE_FILE" ]; then
        cat > "$ZONE_FILE" <<EOF
\$TTL 86400
@   IN  SOA ns1.$DOMAIN. admin.$DOMAIN. (
        $(date +%Y%m%d%H) ; Serial
        3600       ; Refresh
        1800       ; Retry
        604800     ; Expire
        86400 )    ; Minimum TTL

    IN  NS  ns1.$DOMAIN.
    IN  A   $IP

ns1 IN  A   $IP
*   IN  A   $IP
EOF
        sudo chown named:named "$ZONE_FILE"
        sudo chmod 640 "$ZONE_FILE"
    fi

    # Ajoute la zone dans named.conf si absente
    if ! grep -q "zone \"$DOMAIN\"" "$DNS_CONF"; then
        cat >> "$DNS_CONF" <<EOF

zone "$DOMAIN" {
    type master;
    file "$ZONE_FILE";
};
EOF
    fi

    # Corrige named.conf pour listen-on any et allow-query any
    sudo sed -i 's/listen-on port 53.*/listen-on port 53 { any; };/' "$DNS_CONF"
    sudo sed -i 's/listen-on-v6 port 53.*/listen-on-v6 port 53 { any; };/' "$DNS_CONF"
    sudo sed -i 's/allow-query.*/allow-query     { any; };/' "$DNS_CONF"

    # Vérifie la syntaxe de la zone
    sudo named-checkzone "$DOMAIN" "$ZONE_FILE"
    sudo systemctl restart named
}

create_user() {
    CLIENT=$1
    DOMAIN=$2
    WEB_DIR="$WEB_ROOT/$CLIENT"
    SUBDOMAIN="$CLIENT.$DOMAIN"
    DB_NAME="${CLIENT}_db"
    DB_USER="${CLIENT}_user"
    DB_PASS=$(openssl rand -base64 12)
    USER_PASS=$(openssl rand -base64 12)
    IP=$(curl -s ifconfig.me)
    ZONE_FILE="$DNS_ZONE_DIR/$DOMAIN.db"

    log "Création de $CLIENT.$DOMAIN"

    # User system
    if ! id "$CLIENT" &>/dev/null; then
        useradd -m -s /bin/bash "$CLIENT"
        echo "$CLIENT:$USER_PASS" | chpasswd
    fi

    # Répertoire web
    mkdir -p "$WEB_DIR"
    chown -R "$CLIENT:$CLIENT" "$WEB_DIR"
    chmod 2775 "$WEB_DIR"

    # DNS : Ajoute l'entrée uniquement si elle n'existe pas déjà
    if ! grep -q "^$CLIENT[[:space:]]\+IN[[:space:]]\+A" "$ZONE_FILE"; then
        echo "$CLIENT IN A $IP" | sudo tee -a "$ZONE_FILE" >/dev/null
    fi
    # Mise à jour du serial (10 chiffres AAAAMMJJHH)
    sudo sed -i "0,/SOA.*(/s/\([0-9]\{10\}\)/$(date +%Y%m%d%H)/" "$ZONE_FILE"
    sudo rndc reload "$DOMAIN"

    # Apache VirtualHost
    cat > "/etc/httpd/conf.d/$CLIENT.conf" <<EOF
<VirtualHost *:80>
    ServerName $SUBDOMAIN
    DocumentRoot $WEB_DIR

    <Directory $WEB_DIR>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
EOF

    # Page d'accueil dynamique
    cat > "$WEB_DIR/index.php" <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>$SUBDOMAIN</title>
    <style>
        .file-list { border: 1px solid #ddd; padding: 15px; }
        .file-item { font-family: monospace; }
    </style>
</head>
<body>
    <h1>Bienvenue sur $SUBDOMAIN</h1>
    <div class="file-list">
        <?php
        foreach (scandir(__DIR__) as \$file) {
            if (!in_array(\$file, ['.', '..'])) {
                echo '<div class="file-item">' . htmlspecialchars(\$file) . '</div>';
            }
        }
        ?>
    </div>
</body>
</html>
EOF
    chown "$CLIENT:$CLIENT" "$WEB_DIR/index.php"

    # MariaDB
    mysql -u root <<MYSQL_SCRIPT
CREATE DATABASE IF NOT EXISTS $DB_NAME;
CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';
GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';
FLUSH PRIVILEGES;
MYSQL_SCRIPT

    # FTP
    sudo mkdir -p /etc/vsftpd
    sudo touch /etc/vsftpd/user_list
    sudo chmod 600 /etc/vsftpd/user_list
    grep -qxF "$CLIENT" /etc/vsftpd/user_list || echo "$CLIENT" | sudo tee -a /etc/vsftpd/user_list >/dev/null
    sudo systemctl restart vsftpd

    # Samba
    if ! grep -q "^\[$CLIENT\]" /etc/samba/smb.conf; then
        cat >> /etc/samba/smb.conf <<EOF

[$CLIENT]
    path = $WEB_DIR
    valid users = $CLIENT
    writable = yes
    browseable = yes
    create mask = 0644
    directory mask = 0755
EOF
    fi
    (echo "$USER_PASS"; echo "$USER_PASS") | smbpasswd -a "$CLIENT" -s
    sudo systemctl restart smb nmb

    # Résumé
    echo "======== $SUBDOMAIN ========"
    echo "Web: http://$SUBDOMAIN"
    echo "FTP/Samba: $CLIENT/$USER_PASS"
    echo "MySQL: $DB_USER/$DB_PASS"
}

# Main
if [ "$EUID" -ne 0 ]; then
    echo "Exécutez en tant que root !" >&2
    exit 1
fi

case $1 in
    "full")
        dnf install -y --allowerasing curl
        dnf install -y bind httpd mariadb105-server vsftpd samba php-fpm php-mysqlnd
        fix_firewall
        fix_resolv_conf
        fix_apache_servername
        systemctl enable --now named httpd mariadb vsftpd smb nmb php-fpm
        configure_dns "$3"
        create_user "$2" "$3"
        systemctl restart httpd
        ;;
    "user")
        fix_firewall
        fix_resolv_conf
        fix_apache_servername
        systemctl enable --now named httpd mariadb vsftpd smb nmb php-fpm
        create_user "$2" "$3"
        systemctl restart httpd
        ;;
    *)
        echo "Usage:"
        echo "  Configuration complète : sudo $0 full NOM_CLIENT DOMAINE"
        echo "  Ajout utilisateur     : sudo $0 user NOM_CLIENT DOMAINE"
        exit 1
        ;;
esac

log "Déploiement terminé avec succès"
