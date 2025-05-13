#!/bin/bash
set -e

# =============================
# Script de création de client web
# Usage: sudo ./create-client.sh NOM_CLIENT DOMAINE
# =============================

# Vérification de l'utilisateur root
if [ "$EUID" -ne 0 ]; then
    echo "Ce script doit être exécuté en tant que root (sudo)" >&2
    exit 1
fi

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 NOM_CLIENT DOMAINE"
    exit 1
fi

CLIENT="$1"
DOMAIN="$2"
WEB_ROOT="/var/www"
WEB_DIR="$WEB_ROOT/$CLIENT"
DB_NAME="${CLIENT}_db"
DB_USER="${CLIENT}_user"
DB_PASS=$(openssl rand -base64 12)
USER_PASS=$(openssl rand -base64 12)
LOG_FILE="/var/log/client-creation.log"

echo "======== Début de la création - $(date) ========" | tee -a "$LOG_FILE"
echo "Client: $CLIENT" | tee -a "$LOG_FILE"
echo "Domaine: $DOMAIN" | tee -a "$LOG_FILE"

# 1. Installation des dépendances
dnf install -y httpd mariadb105-server vsftpd samba php-fpm php-mysqlnd > /dev/null

# 2. Activation des services
systemctl enable --now httpd mariadb vsftpd smb nmb php-fpm

# 3. Création du groupe et de l'utilisateur
groupadd webusers 2>/dev/null || true
id -u "$CLIENT" &>/dev/null || useradd -m -G webusers "$CLIENT"
echo "$CLIENT:$USER_PASS" | chpasswd

# 4. Préparation du répertoire web
mkdir -p "$WEB_DIR"
chown -R "$CLIENT:webusers" "$WEB_DIR"
chmod 2775 "$WEB_DIR"

# 5. Configuration Apache
sed -i '/^#ServerName /a ServerName localhost' /etc/httpd/conf/httpd.conf 2>/dev/null || \
    grep -q '^ServerName localhost' /etc/httpd/conf/httpd.conf || \
    echo "ServerName localhost" >> /etc/httpd/conf/httpd.conf

mkdir -p /etc/httpd/sites-available /etc/httpd/sites-enabled

cat > "/etc/httpd/sites-available/$CLIENT.conf" <<EOF
<VirtualHost *:80>
    ServerName $DOMAIN
    DocumentRoot $WEB_DIR

    <Directory $WEB_DIR>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
        DirectoryIndex index.php index.html
    </Directory>

    ErrorLog /var/log/httpd/${CLIENT}-error.log
    CustomLog /var/log/httpd/${CLIENT}-access.log combined
</VirtualHost>
EOF

ln -sf "/etc/httpd/sites-available/$CLIENT.conf" "/etc/httpd/sites-enabled/$CLIENT.conf"

if ! grep -q 'IncludeOptional /etc/httpd/sites-enabled/\*.conf' /etc/httpd/conf/httpd.conf; then
    echo "IncludeOptional /etc/httpd/sites-enabled/*.conf" >> /etc/httpd/conf/httpd.conf
fi

systemctl restart httpd

# 6. Création de la page d'accueil dynamique
cat > "$WEB_DIR/index.php" <<'EOF'
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Bienvenue <?php echo htmlspecialchars(getenv("CLIENT_NAME") ?: "client"); ?></title>
    <style>
        body { font-family: Arial, sans-serif; }
        .file-list { border: 1px solid #ddd; padding: 15px; max-width: 600px; }
        .file-item { padding: 5px; font-family: monospace; }
    </style>
</head>
<body>
    <h1>Bienvenue <?php echo htmlspecialchars(getenv("CLIENT_NAME") ?: "client"); ?> !</h1>
    <p>Domaine : <?php echo htmlspecialchars(getenv("CLIENT_DOMAIN") ?: ""); ?></p>
    <p>Répertoire web : <?php echo htmlspecialchars(getenv("CLIENT_WEBDIR") ?: ""); ?></p>
    <p>Base de données : <?php echo htmlspecialchars(getenv("CLIENT_DBNAME") ?: ""); ?></p>
    <div class="file-list">
        <h2>Fichiers dans votre dossier web :</h2>
        <ul>
        <?php
        \$files = scandir(__DIR__);
        foreach (\$files as \$file) {
            if (!in_array(\$file, ['.', '..', 'index.php'])) {
                echo '<li class="file-item">' . htmlspecialchars(\$file) . '</li>';
            }
        }
        ?>
        </ul>
    </div>
</body>
</html>
EOF

# Variables d'environnement pour la page PHP
echo "SetEnv CLIENT_NAME $CLIENT" > "$WEB_DIR/.htaccess"
echo "SetEnv CLIENT_DOMAIN $DOMAIN" >> "$WEB_DIR/.htaccess"
echo "SetEnv CLIENT_WEBDIR $WEB_DIR" >> "$WEB_DIR/.htaccess"
echo "SetEnv CLIENT_DBNAME $DB_NAME" >> "$WEB_DIR/.htaccess"

chown "$CLIENT:webusers" "$WEB_DIR/index.php" "$WEB_DIR/.htaccess"
chmod 664 "$WEB_DIR/index.php" "$WEB_DIR/.htaccess"

# 7. Configuration MariaDB
systemctl is-active --quiet mariadb || systemctl start mariadb

mysql -u root <<MYSQL_SCRIPT
CREATE DATABASE IF NOT EXISTS $DB_NAME;
CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';
GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';
FLUSH PRIVILEGES;
MYSQL_SCRIPT

# 8. Configuration FTP (vsftpd)
mkdir -p /etc/vsftpd
touch /etc/vsftpd/user_list
chmod 600 /etc/vsftpd/user_list
grep -qxF "$CLIENT" /etc/vsftpd/user_list || echo "$CLIENT" >> /etc/vsftpd/user_list

cat > /etc/vsftpd/vsftpd.conf <<EOF
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=YES
xferlog_enable=YES
connect_from_port_20=YES
chroot_local_user=YES
allow_writeable_chroot=YES
pasv_enable=YES
pasv_min_port=30000
pasv_max_port=31000
userlist_enable=YES
userlist_file=/etc/vsftpd/user_list
userlist_deny=NO
EOF

systemctl restart vsftpd

# 9. Configuration Samba
cat >> /etc/samba/smb.conf <<EOF

[$CLIENT]
    comment = Partage Web $CLIENT
    path = $WEB_DIR
    valid users = $CLIENT
    writable = yes
    browseable = yes
    create mask = 0644
    directory mask = 0755
EOF

(echo "$USER_PASS"; echo "$USER_PASS") | smbpasswd -a "$CLIENT" -s
systemctl restart smb nmb

# 10. Résumé des informations
echo "==========================================" | tee -a "$LOG_FILE"
echo "Création terminée avec succès !" | tee -a "$LOG_FILE"
echo "Accès FTP/Samba :" | tee -a "$LOG_FILE"
echo "  Utilisateur : $CLIENT" | tee -a "$LOG_FILE"
echo "  Mot de passe : $USER_PASS" | tee -a "$LOG_FILE"
echo "Accès Web : http://$DOMAIN/" | tee -a "$LOG_FILE"
echo "Base de données :" | tee -a "$LOG_FILE"
echo "  Nom : $DB_NAME" | tee -a "$LOG_FILE"
echo "  Utilisateur : $DB_USER" | tee -a "$LOG_FILE"
echo "  Mot de passe : $DB_PASS" | tee -a "$LOG_FILE"
echo "==========================================" | tee -a "$LOG_FILE"
