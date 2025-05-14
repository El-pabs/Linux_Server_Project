#!/bin/bash

clear

RED='\033[0;31m' 
BLUE='\e[38;5;33m' 
NC='\033[0m' 

updatedb
systemctl enable --now cockpit
dnf install firewalld
y
systemctl enable --now firewalld
systemctl start firewalld
firewall-cmd --permanent --zone=public --add-service=cockpit
firewall-cmd --reload

dnf -y install nfs-utils samba mlocate bind chrony fail2ban vsftpd rsync clamav clamav-scanner-systemd clamav-update cockpit bind-utils httpd php php-mysqlnd mariadb-server phpmyadmin


clear

display_menu() {
    echo ""
    echo "|----------------------------------------------------------------------|"
    echo -e "|                 ${BLUE}Welcome to the server assistant ${NC}                     |"
    echo "|              Please select the tool you want to use                  |"
    echo "|----------------------------------------------------------------------|"
    echo "| 0. Set server hostname                                               |"
    echo "| 1. RAID Configuration                                                |"
    echo "| 2. NFS                                                               |"
    echo "| 3. Web services management                                           |"
    echo "| 4. NTP Time Server                                                   |"
    echo "| 5. Install clamav et fail2ban                                        |"
    echo "| 6. Backup                                                            |"
    echo "| 7. Consult Logs Dashboard                                            |"
    echo "| 8. Installer Netdata (monitoring)                                    |"
    echo "|----------------------------------------------------------------------|"
    echo "| q. Quit                                                              |"
    echo "|----------------------------------------------------------------------|"
    echo ""
}

display_hostname_menu() {
    echo ""
    echo "|----------------------------------------------------------------------|"
    echo -e "|                     ${BLUE}Hostname Configuration Menu ${NC}                     |"
    echo "|----------------------------------------------------------------------|"
    echo "| 1. Set hostname                                                      |"
    echo "| 2. Display current hostname                                          |"
    echo "|----------------------------------------------------------------------|"
    echo "| q. Quit                                                              |"
    echo "|----------------------------------------------------------------------|"
    echo ""
}

display_raid_menu() {
    echo ""
    echo "|----------------------------------------------------------------------|"
    echo -e "|                 ${BLUE}RAID Configuration Menu ${NC}                     |"
    echo "|----------------------------------------------------------------------|"
    echo "| 1. Create RAID                                                       |"
    echo "| 2. Display current RAID                                              |"
    echo "|----------------------------------------------------------------------|"
    echo "| q. Quit                                                              |"
    echo "|----------------------------------------------------------------------|"
    echo ""
}

display_unauth_share_menu() {
    echo ""
    echo "|----------------------------------------------------------------------|"
    echo -e "|                ${BLUE}Welcome to the unauth share assistant ${NC}                |"
    echo "|              Please select the tool you want to use                  |"
    echo "|----------------------------------------------------------------------|"
    echo "| 0. Activate NFS                                                      |"
    echo "|----------------------------------------------------------------------|"
    echo "| q. Quit                                                              |"
    echo "|----------------------------------------------------------------------|"
    echo ""
}

display_web_menu() {
    echo ""
    echo "|----------------------------------------------------------------------|"
    echo -e "|                ${BLUE}Welcome To The User Management Menu ${NC}                  |"
    echo "|               Please select the tool you want to use                 |"
    echo "|----------------------------------------------------------------------|"
    echo "| 0. Basic setup (main DNS, web, DB)                                   |"
    echo "| 1. Add User                                                          |"
    echo "| 2. Remove User                                                       |"
    echo "|----------------------------------------------------------------------|"
    echo "| q. Quit                                                              |"
    echo "|----------------------------------------------------------------------|"
    echo ""
}

display_ntp_menu() {
    echo "|-------------------------------------------|"
    echo -e "|            ${GREEN}NTP server wizard${NC}              |"
    echo "|-------------------------------------------|"
    echo "|         What do you want to do?           |"
    echo "|-------------------------------------------|"
    echo "| 1. Setup the NTP (defaults to Eu/Bx)      |"
    echo "| 2. Choose a timezone                      |"
    echo "| 3. Show NTP statuses                      |"
    echo "|-------------------------------------------|"
    echo "| q. Quit                                   |"
    echo "|-------------------------------------------|"
    echo ""
}

set_hostname() {
while true; do

    clear
    display_hostname_menu
    read -p "Enter your choice: " hostname_choice
    case $hostname_choice in
        1) read -p "Enter the new hostname: " new_hostname
           hostnamectl set-hostname $new_hostname
           echo "Hostname set to $new_hostname"
           echo "Press any key to continue..."
           read -n 1 -s key
           clear
           ;;
        2) current_hostname=$(hostnamectl --static)
           echo "Current hostname: $current_hostname"
               echo "Press any key to continue..."
               read -n 1 -s key
               clear
           ;;
        q|Q) clear && echo "Exiting hostname configuration menu" && break ;;
        *) clear && echo "Invalid choice. Please enter a valid option." ;;
    esac
done
}

raid(){
    clear
    echo "=== Création d'un RAID logiciel ==="

    # Afficher les devices RAID existants
    echo "RAID existants :"
    cat /proc/mdstat
    echo

    # Demander à l'utilisateur le nom du device RAID à créer
    read -p "Nom du device RAID à créer (ex: md0, md1) : " RAID_NAME
    RAID_DEVICE="/dev/$RAID_NAME"

    # Lister les disques disponibles
    echo "Disques disponibles :"
    lsblk -d -o NAME,SIZE,TYPE | grep disk
    echo

    # Demander à l'utilisateur les disques à utiliser (ex: sdb sdc sdd)
    read -p "Entrez les disques à utiliser pour le RAID (ex: sdb sdc sdd) : " DISKS
    RAID_DISKS=""
    for disk in $DISKS; do
        RAID_DISKS="$RAID_DISKS /dev/$disk"
    done

    # Installer les outils nécessaires
    sudo dnf install lvm2 mdadm -y

    # Créer le RAID
    sudo mdadm --create --verbose $RAID_DEVICE --level=5 --raid-devices=$(echo $DISKS | wc -w) $RAID_DISKS

    # LVM et formatage
    sudo pvcreate $RAID_DEVICE
    sudo vgcreate vg_raid5 $RAID_DEVICE

    # Partition pour les partages
    sudo lvcreate -L 500M -n share vg_raid5
    sudo mkfs.ext4 /dev/vg_raid5/share
    sudo mkdir -p /mnt/raid5_share
    sudo mount -o noexec,nosuid,nodev /dev/vg_raid5/share /mnt/raid5_share
    sudo blkid /dev/vg_raid5/share | awk '{print $2 " /mnt/raid5_share ext4 defaults 0 0"}' | sudo tee -a /etc/fstab

    # Partition pour le web
    sudo lvcreate -L 500M -n web vg_raid5
    sudo mkfs.ext4 /dev/vg_raid5/web
    sudo mkdir -p /mnt/raid5_web
    sudo mount -o noexec,nosuid,nodev /dev/vg_raid5/web /mnt/raid5_web
    sudo blkid /dev/vg_raid5/web | awk '{print $2 " /mnt/raid5_web ext4 defaults 0 0"}' | sudo tee -a /etc/fstab

    # Partition dédiée au backup
    sudo lvcreate -L 500M -n backup vg_raid5
    sudo mkfs.ext4 /dev/vg_raid5/backup
    sudo mkdir -p /mnt/raid5_backup
    sudo mount -o noexec,nosuid,nodev /dev/vg_raid5/backup /mnt/raid5_backup
    sudo blkid /dev/vg_raid5/backup | awk '{print $2 " /mnt/raid5_backup ext4 defaults 0 0"}' | sudo tee -a /etc/fstab

    echo "Le dossier de backup est prêt : /mnt/raid5_backup"
    echo "Utilise ce chemin comme destination dans ton script de sauvegarde."
    systemctl daemon-reload
    df -h
    read -n 1 -s -p "Appuyez sur une touche pour continuer..."
}

unauthshare(){
    smb(){
    echo "Installing Samba share"
    sudo mkdir -p /mnt/raid5_share

    quotacheck -cug /mnt/raid5_share
    quotaon /mnt/raid5_share
    edquota -u nobody -f /mnt/raid5_share -s 500M -h 600M
    dnf update -y
    dnf -y install samba samba-client
    systemctl enable smb --now
    systemctl enable nmb --now    

    firewall-cmd --permanent --add-service=samba
    firewall-cmd --reload

    chown -R nobody:nobody /mnt/raid5_share
    chmod -R 0777 /mnt/raid5_share
    
    cat <<EOL > /etc/samba/smb.unauth.conf
[unauth_share]
   path = /mnt/raid5_share/
   browsable = yes
   writable = yes
   guest ok = yes
   guest only = yes
   force user = nobody
   force group = nobody
   create mask = 0777
   directory mask = 0777
   read only = no
EOL
    
    PRIMARY_CONF="/etc/samba/smb.conf"
    INCLUDE_LINE="include = /etc/samba/smb.unauth.conf"

    if ! grep -Fxq "$INCLUDE_LINE" "$PRIMARY_CONF"; then
        echo "$INCLUDE_LINE" >> "$PRIMARY_CONF"
        echo "Include line added to $PRIMARY_CONF"
    else
        echo "Include line already exists in $PRIMARY_CONF"
    fi

    # SELINUX 
    /sbin/restorecon -R -v /mnt/raid5_share
    setsebool -P samba_export_all_rw 1

    systemctl restart smb
    systemctl restart nmb

    echo "Samba services restarted"

    echo "Press any key to continue..."
    read -n 1 -s key
	clear
}

nfs(){
    echo "Installing NFS share"
    sudo mkdir -p /mnt/raid5_share
    dnf update -y
    dnf -y install nfs-utils
    systemctl enable nfs-server --now
    firewall-cmd --permanent --add-service=nfs
    firewall-cmd --permanent --add-service=mountd
    firewall-cmd --permanent --add-service=rpc-bind
    firewall-cmd --reload
    echo "/mnt/raid5_share *(rw,sync,no_root_squash)" > /etc/exports
    exportfs -a
    systemctl restart nfs-server
    echo "NFS services restarted"
    echo "Press any key to continue..."
    read -n 1 -s key
    clear
}

    clear
    echo "Starting unauthshare"
    while true; do
        display_unauth_share_menu
        read -p "Enter your choice: " choice
        case $choice in
            0) nfs ;;
            1) smb ;;
            q|Q) clear && echo "Exiting the web server configuration wizard." && break ;;
            *) clear && echo "Invalid choice. Please enter a valid option." ;;
        esac
    done

}

generate_ssl_cert() {
    DOMAIN=$1
    SSL_DIR="/etc/ssl/$DOMAIN"
    mkdir -p "$SSL_DIR"

    # Variables de nommage
    CA_KEY="$SSL_DIR/myCA.key"
    CA_CERT="$SSL_DIR/myCA.pem"
    SERVER_KEY="$SSL_DIR/server.key"
    SERVER_CSR="$SSL_DIR/server.csr"
    SERVER_CERT="$SSL_DIR/server.crt"
    EXT_FILE="$SSL_DIR/server.ext"

    # Génération de la CA locale (si non existante)
    if [ ! -f "$CA_KEY" ]; then
        openssl genrsa -out "$CA_KEY" 2048
        openssl req -x509 -new -key "$CA_KEY" -sha256 -days 1825 \
            -subj "/C=FR/ST=France/L=Paris/O=MyOrg/OU=IT/CN=MyCA" \
            -out "$CA_CERT"
    fi

    # Génération de la clé serveur
    openssl genrsa -out "$SERVER_KEY" 2048

    # Génération du CSR
    openssl req -new -key "$SERVER_KEY" -out "$SERVER_CSR" \
        -subj "/C=FR/ST=Belgique/L=Mons/O=MyOrg/OU=Web/CN=$DOMAIN"

    # Fichier d'extension pour le SAN
    cat > "$EXT_FILE" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = $DOMAIN
EOF

    # Signature du certificat serveur par la CA locale
    openssl x509 -req -in "$SERVER_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
        -out "$SERVER_CERT" -days 825 -sha256 -extfile "$EXT_FILE"

    # Copie dans les emplacements standards d'Apache
    cp "$SERVER_CERT" /etc/pki/tls/certs/"$DOMAIN.crt"
    cp "$SERVER_KEY" /etc/pki/tls/private/"$DOMAIN.key"
}

webservices() {
    WEB_ROOT="/var/www"
    DNS_ZONE_DIR="/var/named"
    DNS_CONF="/etc/named.conf"
    LOG_FILE="/var/log/deploy.log"

    log() {
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
    }

    fix_firewall() {
        if systemctl is-active --quiet firewalld; then
            log "Configuration du firewall local (firewalld)"
            sudo firewall-cmd --permanent --add-service=http
            sudo firewall-cmd --permanent --add-service=https
            sudo firewall-cmd --permanent --add-service=ftp
            sudo firewall-cmd --permanent --add-port=53/tcp
            sudo firewall-cmd --permanent --add-port=53/udp
            sudo firewall-cmd --permanent --add-port=30000-31000/tcp
            firewall-cmd --permanent --add-service=samba
            sudo firewall-cmd --reload
        fi
    }

    fix_resolv_conf() {
        if ! grep -q "^nameserver 127.0.0.1" /etc/resolv.conf; then
            log "Ajout de nameserver 127.0.0.1 dans /etc/resolv.conf"
            sudo sed -i '1inameserver 127.0.0.1' /etc/resolv.conf
        fi
    }

    fix_apache_servername() {
        if ! grep -q "^ServerName" /etc/httpd/conf/httpd.conf; then
            echo "ServerName localhost" | sudo tee -a /etc/httpd/conf/httpd.conf
        fi
    }

    configure_dns() {
        DOMAIN=$1
        IP=$(hostname -I | awk '{print $1}')
        IPReverse="$(echo $IP | awk -F. '{print $3"."$2"."$1".in-addr.arpa"}')"
        ZONE_FILE="$DNS_ZONE_DIR/$DOMAIN.db"
        REVERSE_ZONE_FILE="$DNS_ZONE_DIR/$IPReverse"
        last_octet=$(echo $IP | cut -d. -f4)


        log "Configuration DNS pour $DOMAIN"

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

sudo tee "$REVERSE_ZONE_FILE" > /dev/null <<EOF
\$TTL 86400
@   IN  SOA ns1.${DOMAIN}. admin.${DOMAIN}. (
        $(date +%Y%m%d%H) ; Serial
        3600    ; Refresh
        1800    ; Retry
        1209600 ; Expire
        86400 ) ; Minimum TTL

@       IN  NS  ns1.${DOMAIN}.
$last_octet      IN  PTR ns1.${DOMAIN}.
EOF

            sudo chown named:named "$ZONE_FILE"
            sudo chmod 640 "$ZONE_FILE"
        fi
        if ! grep -q "zone \"$DOMAIN\"" "$DNS_CONF"; then
            cat >> "$DNS_CONF" <<EOF

zone "$DOMAIN" {
    type master;
    file "$ZONE_FILE";
};

zone "$IPReverse" IN {
    type master;
    file "$REVERSE_ZONE_FILE";
};

EOF
        fi

        sudo sed -i 's/listen-on port 53.*/listen-on port 53 { any; };/' "$DNS_CONF"
        sudo sed -i 's/listen-on-v6 port 53.*/listen-on-v6 port 53 { any; };/' "$DNS_CONF"
        sudo sed -i 's/allow-query.*/allow-query     { any; };/' "$DNS_CONF"

        sudo named-checkzone "$DOMAIN" "$ZONE_FILE"
        sudo systemctl restart named
    }

    create_user() {
        dnf install -y mod_ssl
        CLIENT=$1
        DOMAIN=$2
        WEB_DIR="$WEB_ROOT/$CLIENT"
        SUBDOMAIN="$CLIENT.$DOMAIN"
        DB_NAME="${CLIENT}_db"
        DB_USER="${CLIENT}_user"
        DB_PASS="sherpa"
        USER_PASS="sherpa"
        IP=$(hostname -I | awk '{print $1}')
        ZONE_FILE="$DNS_ZONE_DIR/$DOMAIN.db"

        log "Création de $CLIENT.$DOMAIN"

        if ! id "$CLIENT" &>/dev/null; then
            useradd -m -s /bin/bash "$CLIENT"
            echo "$CLIENT:$USER_PASS" | chpasswd
        fi

        (echo "$USER_PASS"; echo "$USER_PASS") | smbpasswd -a "$CLIENT" -s

        mkdir -p "$WEB_DIR"
        chown -R "$CLIENT:$CLIENT" "$WEB_DIR"
        chmod 2775 "$WEB_DIR"

        # Ajout du partage Samba privé pour l'utilisateur, si non déjà présent
        if ! grep -q "^\[$CLIENT\]" /etc/samba/smb.conf; then
            cat <<EOF | sudo tee -a /etc/samba/smb.conf > /dev/null

[$CLIENT]
    path = $WEB_DIR
    valid users = $CLIENT
    writable = yes
    create mask = 0770
    directory mask = 0770
    force user = $CLIENT
    force group = $CLIENT
EOF
        fi

        sudo systemctl restart smb nmb

        if ! grep -q "^$CLIENT[[:space:]]\+IN[[:space:]]\+A" "$ZONE_FILE"; then
            echo "$CLIENT IN A $IP" | sudo tee -a "$ZONE_FILE" >/dev/null
        fi
        sudo sed -i "0,/SOA.*(/s/\([0-9]\{10\}\)/$(date +%Y%m%d%H)/" "$ZONE_FILE"
        sudo rndc reload "$DOMAIN"

        # --- Création du virtualhost HTTP ---
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

        # --- Génération du certificat SSL et VirtualHost HTTPS ---
        generate_ssl_cert "$SUBDOMAIN"

        cat > "/etc/httpd/conf.d/$CLIENT-ssl.conf" <<EOF
<VirtualHost *:443>
    ServerName $SUBDOMAIN
    DocumentRoot $WEB_DIR
    SSLEngine on
    SSLCertificateFile /etc/pki/tls/certs/$SUBDOMAIN.crt
    SSLCertificateKeyFile /etc/pki/tls/private/$SUBDOMAIN.key
    <Directory $WEB_DIR>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    ErrorLog logs/${CLIENT}_ssl_error.log
    CustomLog logs/${CLIENT}_ssl_access.log combined
</VirtualHost>
EOF

        systemctl restart httpd

        cat > "$WEB_DIR/index.php" <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>$SUBDOMAIN</title>
    <style>
        .file-list { border: 1px solid #ddd; padding: 15px; }
        .file-item { font-family: monospace; margin-bottom: 5px; }
    </style>
</head>
<body>
    <h1>Bienvenue sur $SUBDOMAIN</h1>
    <div class="file-list">
        <?php
        foreach (scandir(__DIR__) as \$file) {
            if (!in_array(\$file, ['.', '..', 'index.php'])) {
                echo '<div class="file-item"><a href="' . rawurlencode(\$file) . '" download>' . htmlspecialchars(\$file) . '</a></div>';
            }
        }
        ?>
    </div>
</body>
</html>
EOF
        chown "$CLIENT:$CLIENT" "$WEB_DIR/index.php"

        mysql -u root <<MYSQL_SCRIPT
CREATE DATABASE IF NOT EXISTS $DB_NAME;
CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';
GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';
FLUSH PRIVILEGES;
MYSQL_SCRIPT

        sudo mkdir -p /etc/vsftpd
        sudo touch /etc/vsftpd/user_list
        sudo chmod 600 /etc/vsftpd/user_list
        grep -qxF "$CLIENT" /etc/vsftpd/user_list || echo "$CLIENT" | sudo tee -a /etc/vsftpd/user_list >/dev/null
        
        mkdir -p /var/run/vsftpd/empty
        chown root:root /var/run/vsftpd/empty
        chmod 755 /var/run/vsftpd/empty

        mkdir -p /etc/pki/tls/private /etc/pki/tls/certs
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/pki/tls/private/vsftpd.key \
        -out /etc/pki/tls/certs/vsftpd.pem \
        -subj "/C=BE/ST=Hainaut/L=Mons/O=inox.lan/CN=ftp.$DOMAIN"


        sudo mkdir -p /srv/samba/public
        sudo chmod 0777 /srv/samba/public
        sudo chown nobody:nobody /srv/samba/public
        sudo chown -R nobody:nobody /srv/samba/public
        sudo chmod -R 0777 /srv/samba/public

        if ! grep -q "^\[public\]" /etc/samba/smb.conf; then
            cat >> /etc/samba/smb.conf <<EOF

[public]
    path = /srv/samba/public
    guest ok = yes
    guest only = yes
    writable = yes
    force user = nobody
    force group = nobody
    create mask = 0666
    directory mask = 0777
    browseable = yes
EOF
        fi

        if ! grep -q "^\[homes\]" /etc/samba/smb.conf; then
            cat >> /etc/samba/smb.conf <<EOF
[homes]
    comment = Home Directories
    browseable = no
    writable = yes
EOF
        fi

        sudo sed -i '/^\[global\]/,/^\[/ s/^.*map to guest.*$/map to guest = Bad User/' /etc/samba/smb.conf
        if ! grep -q 'map to guest' /etc/samba/smb.conf; then
            sed -i '/^\[global\]/a map to guest = Bad User' /etc/samba/smb.conf
        fi

        sudo systemctl restart smb nmb

        if ! grep -q "/srv/samba/public" /etc/exports; then
            echo "/srv/samba/public *(rw,sync,no_subtree_check,no_root_squash)" | sudo tee -a /etc/exports
            sudo exportfs -ra
            sudo systemctl enable --now nfs-server
        fi

        (echo "$USER_PASS"; echo "$USER_PASS") | smbpasswd -a "$CLIENT" -s
        echo "userlist_deny=NO" | sudo tee -a /etc/vsftpd/vsftpd.conf
        sudo systemctl restart vsftpd
        sudo systemctl restart smb nmb

    cat > /etc/vsftpd/vsftpd.conf <<EOF
ftpd_banner=Bienvenue sur le serveur FTP sécurisé.
xferlog_enable=YES
anonymous_enable=NO
local_enable=YES
write_enable=YES
chroot_local_user=YES
allow_writeable_chroot=YES
userlist_enable=YES
userlist_deny=NO
local_umask=022
user_sub_token=\$USER
local_root=/var/www/\$USER
secure_chroot_dir=/var/run/vsftpd/empty
pasv_min_port=30000
pasv_max_port=30100
listen_port=21
listen=YES
listen_ipv6=NO
pam_service_name=vsftpd
ssl_enable=YES
rsa_cert_file=/etc/pki/tls/certs/vsftpd.pem
rsa_private_key_file=/etc/pki/tls/private/vsftpd.key
force_local_data_ssl=YES
force_local_logins_ssl=YES
ssl_tlsv1=YES
ssl_sslv2=NO
ssl_sslv3=NO
require_ssl_reuse=NO
EOF

    systemctl restart vsftpd


        echo "======== $SUBDOMAIN ========"
        echo "Web: http://$SUBDOMAIN"
        echo "FTP/Samba: $CLIENT/$USER_PASS"
        echo "MySQL: $DB_USER/$DB_PASS"
}

    generate_ssl_cert() {
    DOMAIN=$1
    mkdir -p /etc/pki/tls/certs /etc/pki/tls/private
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "/etc/pki/tls/private/$DOMAIN.key" \
        -out "/etc/pki/tls/certs/$DOMAIN.crt" \
        -subj "/C=FR/ST=Default/L=Default/O=Default/CN=$DOMAIN"
}

    log() { echo "[+] $1"; }


    if [ "$EUID" -ne 0 ]; then
        echo "Exécutez en tant que root !" >&2
        exit 1
    fi

    echo "Choisissez le mode d'installation :"
    echo "  1) Installation complète (full)"
    echo "  2) Ajout utilisateur (user)"
    read -p "Votre choix (1/2) : " mode_choice
    case "$mode_choice" in
        1)
            MODE="full"
            ;;
        2)
            MODE="user"
            ;;
        *)
            echo "Choix invalide."
            return 1
            ;;
    esac

    read -p "Nom du client (ex: client1) : " CLIENT
    read -p "Domaine (ex: test.lan) : " DOMAIN

    if [[ -z "$CLIENT" || -z "$DOMAIN" ]]; then
        echo "Le client et le domaine sont obligatoires."
        return 1
    fi

    if [ "$MODE" = "full" ]; then
        dnf install -y --allowerasing curl
        dnf install -y bind httpd mariadb105-server vsftpd samba php-fpm php-mysqlnd
        fix_firewall
        fix_resolv_conf
        fix_apache_servername
        systemctl enable --now named httpd mariadb vsftpd smb nmb php-fpm
        configure_dns "$DOMAIN"
        create_user "$CLIENT" "$DOMAIN"
        systemctl restart httpd
    elif [ "$MODE" = "user" ]; then
        fix_firewall
        fix_resolv_conf
        fix_apache_servername
        systemctl enable --now named httpd mariadb vsftpd smb nmb php-fpm
        create_user "$CLIENT" "$DOMAIN"
        systemctl restart httpd
    fi

    log "Déploiement terminé avec succès"

    echo "Press any key to continue..."
    read -n 1 -s key
}




ntp(){
    clear
    echo "Starting ntp"

    setup_ntp() {
    clear 

    ip_server=$(hostname -I | sed 's/ *$//')/16
    ntp_pool="server 0.pool.ntp.org iburst\\nserver 1.pool.ntp.org iburst\\nserver 2.pool.ntp.org iburst\\nserver 3.pool.ntp.org iburst"
    dnf install chrony -y
    systemctl enable --now chronyd
    timedatectl set-timezone Europe/Brussels
    echo "Time zone set to Europe/Brussels"
    timedatectl set-ntp yes
    sed -i "s|#allow 192.168.0.0/16|allow $ip_server|g" /etc/chrony.conf
    sed -i "s/pool 2.almalinux.pool.ntp.org iburst/$ntp_pool/g" /etc/chrony.conf
    systemctl restart chronyd
    echo "Chrony restarted"

    echo "Press any key to continue..."
    read -n 1 -s key
}

timezone_choice() {
    clear

    timezones=$(timedatectl list-timezones)
    echo "Available timezones:"
    PS3="Please select a timezone by number: "

    select timezone in $timezones; do
    if [[ -n $timezone ]]; then
        echo "You selected $timezone"
        break
    else
        echo "Invalid selection. Please try again."
    fi
    done

    echo "Changing timezone to $timezone..."
    timedatectl set-timezone "$timezone"

    echo -e "\nTimezone changed successfully. Current timezone is now:"
    timedatectl | grep "Time zone"

    echo "Press any key to exit..."
    read -n 1 -s key

}

timezone_display() {
    clear

    echo "System Time and Date Information"
    echo "--------------------------------"

    echo -e "\nCurrent System Date and Time:"
    date

    echo -e "\nHardware Clock (RTC) Time:"
    hwclock

    echo -e "\nCurrent Timezone:"
    timedatectl | grep "Time zone"

    echo -e "\nTimedatectl Status:"
    timedatectl status

    echo -e "\nNTP Synchronization Status (timedatectl):"
    timedatectl show-timesync --all

    if command -v chronyc &> /dev/null; then
        echo -e "\nChrony Tracking Information:"
        chronyc tracking

        echo -e "\nChrony Sources:"
        chronyc sources

        echo -e "\nChrony Source Statistics:"
        chronyc sourcestats

        echo -e "\nChrony NTP Data:"
        chronyc ntpdata
    else
        echo -e "\nChrony is not installed or not found. Skipping chrony information."
    fi

    echo "--------------------------------"
    echo "All time and date information displayed successfully."

    # chronyc tracking
    # chronyc sources
    # cat /etc/chrony.conf
    echo "Press any key to exit..."
    read -n 1 -s key
}


        clear
        display_ntp_menu
        read -p "Enter your choice: " choice
        case $choice in
            1) setup_ntp ;;
            2) timezone_choice ;;
            3) timezone_display ;;
            q|Q) clear && echo "Exiting the web server configuration wizard." && break ;;
            *) clear && echo "Invalid choice. Please enter a valid option." ;;
        esac
}

security(){

configure_clamav(){
    clear
    # Install ClamAV
    dnf update -y
    dnf install clamav -y
    # Update ClamAV database
    freshclam
    echo "Clamav virus definitions updated successfully."
    echo "Note : ClamAV is up to date, but the installed version may not be the lastest available."
    # Schedule regular scans
    # Edit the crontab file and add the daily scan command
    echo "0 2 * * * clamscan -r /" | sudo tee -a /etc/crontab
    # Enable automatic scanning on file access
    systemctl enable clamav-freshclam
    systemctl enable clamd@scan
    # Start ClamAV service
    systemctl start clamav-freshclam
    systemctl start clamd@scan
    # Verify ClamAV status
    systemctl status clamav-freshclam
    systemctl status clamd@scan
    # Configure ClamAV for local socket scanning
    sed -i 's/^#LocalSocket /LocalSocket /' /etc/clamd.d/scan.conf
    sed -i 's/^TCPSocket /#TCPSocket /' /etc/clamd.d/scan.conf
    # Restart ClamAV service to apply changes
    systemctl restart clamd@scan

    echo "Clamav Done..."
    echo "Press any key to continue..."
    read -n 1 -s key
    clear
}
    configure_fail2ban() {
        # Install Fail2Ban
        dnf install fail2ban -y

        # Configure Fail2Ban for SSH
        cat <<EOL > /etc/fail2ban/jail.d/sshd.local
    [sshd]
    enabled = true
    port = ssh
    filter = sshd
    logpath = /var/log/secure
    maxretry = 3
    bantime = 3600
    EOL

        # Configure Fail2Ban for Fedora Cockpit
        cat <<EOL > /etc/fail2ban/jail.d/cockpit.local
    [cockpit]
    enabled = true
    port = http,https
    filter = cockpit
    logpath = /var/log/secure
    maxretry = 3
    bantime = 3600
EOL

        # Restart Fail2Ban service
        systemctl enable --now fail2ban

        echo "Fail2Ban configured for SSH and Fedora Cockpit."
        echo "Press any key to continue..."
        read -n 1 -s key
    }
    configure_clamav
    configure_fail2ban

}


backup(){
    clear
    echo "🛠️ Configuration des sauvegardes automatiques (systemd timers)"
    echo
    echo "Détection des volumes RAID disponibles :"
    sudo mdadm --detail --scan
    echo
    echo "Conseil : Il est recommandé de stocker la sauvegarde sur un volume RAID pour plus de sécurité."
    echo

    echo "Points de montage disponibles pour la sauvegarde :"
    # Liste uniquement les points de montage montés sur un dossier (commençant par /)
    options=()
    mapfile -t options < <(lsblk -o MOUNTPOINT,NAME,FSTYPE,SIZE -nr | awk '$1 ~ /^\// {print $1 " (" $2 " " $3 " " $4 ")"}')
    options+=("Entrer un chemin personnalisé")
    PS3="Sélectionnez le point de montage pour le backup : "
    select MOUNT_CHOICE in "${options[@]}"; do
        if [[ -n "$MOUNT_CHOICE" ]]; then
            if [[ "$MOUNT_CHOICE" == "Entrer un chemin personnalisé" ]]; then
                read -p "Entrez le chemin absolu du dossier de backup : " MOUNT_POINT
            else
                MOUNT_POINT=$(echo "$MOUNT_CHOICE" | awk '{print $1}')
            fi
            break
        else
            echo "Sélection invalide. Essayez encore."
        fi
    done

    echo "Le backup sera effectué dans : $MOUNT_POINT"
    sudo mkdir -p "$MOUNT_POINT"

    # Créer le script de backup avec le bon point de montage
    sudo tee /usr/local/bin/auto_backup.sh > /dev/null <<EOF
#!/bin/bash

LOG_FILE="$MOUNT_POINT/backup.log"
TIMESTAMP=\$(date +"%Y-%m-%d_%H-%M-%S")
BACKUP_DIR="$MOUNT_POINT/\$TIMESTAMP"
mkdir -p "\$BACKUP_DIR"

echo "\$(date) - Début sauvegarde" >> "\$LOG_FILE"
rsync -avz /mnt/raid5_share "\$BACKUP_DIR/" >> "\$LOG_FILE" 2>&1
rsync -avz /mnt/raid5_web "\$BACKUP_DIR/" >> "\$LOG_FILE" 2>&1

mkdir -p "\$BACKUP_DIR/user_databases"
while IFS= read -r USERNAME; do
    mysqldump -u root -prootpassword "\${USERNAME}_db" > "\$BACKUP_DIR/user_databases/\${USERNAME}_db.sql" 2>> "\$LOG_FILE"
done < <(pdbedit -L | cut -d: -f1)

echo "\$(date) - Sauvegarde terminée" >> "\$LOG_FILE"
EOF

    sudo chmod +x /usr/local/bin/auto_backup.sh

    # Créer le service systemd
    sudo tee /etc/systemd/system/backup.service > /dev/null <<'EOF'
[Unit]
Description=Sauvegarde automatique des données

[Service]
Type=oneshot
ExecStart=/usr/local/bin/auto_backup.sh
EOF

    # Créer le timer systemd (1h58)
    sudo tee /etc/systemd/system/backup.timer > /dev/null <<'EOF'
[Unit]
Description=Déclenche la sauvegarde toutes les 1h58

[Timer]
OnBootSec=5min
OnUnitActiveSec=118m
RandomizedDelaySec=30s
AccuracySec=1s

[Install]
WantedBy=timers.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable --now backup.timer

    crontab -l | grep -v "auto_backup.sh" | crontab -

    echo
    echo "✅ Sauvegarde configurée avec succès !"
    echo "▪ Destination : $MOUNT_POINT"
    echo "▪ Intervalle : Toutes les 1h58"
    echo "▪ Logs : $MOUNT_POINT/backup.log"
    echo "▪ Status : systemctl status backup.timer"
    read -n 1 -s -p "Appuyez sur une touche pour continuer..."
}



BLUE='\e[38;5;33m'
NC='\033[0m'

# Menu d'affichage des logs
display_logs_menu() {
    echo ""
    echo "|----------------------------------------------------------------------|"
    echo -e "| ${BLUE}Logs Dashboard${NC} |"
    echo "|----------------------------------------------------------------------|"
    echo "| 1. Afficher les logs Apache (web)                                    |"
    echo "| 2. Afficher les logs Samba (partage)                                 |"
    echo "| 3. Afficher les logs SSH (connexion)                                 |"
    echo "| 4. Afficher les logs Fail2Ban (sécurité)                             |"
    echo "| 5. Afficher les logs système (messages)                              |"
    echo "|----------------------------------------------------------------------|"
    echo "| q. Quitter                                                           |"
    echo "|----------------------------------------------------------------------|"
    echo ""
}

# Fonction pour afficher les logs selon le choix utilisateur
logs() {
    while true; do
        clear
        display_logs_menu
        read -p "Votre choix: " log_choice
        case $log_choice in
            1) # Apache
                echo "---- Derniers logs Apache ----"
                if [ -f /var/log/httpd/access_log ]; then
                    sudo tail -n 50 /var/log/httpd/access_log
                    sudo tail -n 50 /var/log/httpd/error_log
                elif [ -f /var/log/apache2/access.log ]; then
                    sudo tail -n 50 /var/log/apache2/access.log
                    sudo tail -n 50 /var/log/apache2/error.log
                else
                    echo "Aucun log Apache trouvé."
                fi
                read -n 1 -s -p "Appuyez sur une touche pour continuer..." ;;

            2) # Samba
                echo "---- Derniers logs Samba ----"
                if [ -f /var/log/samba/log.smbd ]; then
                    sudo tail -n 50 /var/log/samba/log.smbd
                    sudo tail -n 50 /var/log/samba/log.nmbd
                else
                    echo "Aucun log Samba trouvé."
                fi
                read -n 1 -s -p "Appuyez sur une touche pour continuer..." ;;

            3) echo "---- Derniers logs SSH ----"
                if [ -f /var/log/secure ]; then
                    sudo tail -n 50 /var/log/secure | grep -i sshd
                elif [ -f /var/log/auth.log ]; then
                    sudo tail -n 50 /var/log/auth.log | grep -i sshd
                else
                    echo "Aucun fichier de log SSH trouvé."
                    echo "Affichage des logs SSH via journalctl :"
                    sudo journalctl -u sshd -n 50
                fi
                read -n 1 -s -p "Appuyez sur une touche pour continuer..." ;;

            4) # Fail2Ban
                echo "---- Derniers logs Fail2Ban ----"
                if [ -f /var/log/fail2ban.log ]; then
                    sudo tail -n 50 /var/log/fail2ban.log
                else
                    echo "Affichage via journalctl :"
                    sudo journalctl -u fail2ban -n 50
                fi
                read -n 1 -s -p "Appuyez sur une touche pour continuer..." ;;

            5) # Système
                echo "---- Derniers logs système ----"
                if [ -f /var/log/messages ]; then
                    sudo tail -n 50 /var/log/messages
                elif [ -f /var/log/syslog ]; then
                    sudo tail -n 50 /var/log/syslog
                else
                    echo "Affichage via journalctl :"
                    sudo journalctl -n 50
                fi
                read -n 1 -s -p "Appuyez sur une touche pour continuer..." ;;

            q|Q) clear && echo "Sortie du dashboard de logs." && break ;;
            *) clear && echo "Choix invalide." ;;
        esac
    done
}

install_netdata() {
    clear
    echo "Installation de Docker (si pas déjà installé)..."
    sudo yum install -y docker

    echo "Démarrage et activation de Docker..."
    sudo systemctl enable --now docker

    echo "Ajout de ec2-user au groupe docker (si pas déjà fait)..."
    sudo usermod -aG docker ec2-user

    echo "Déploiement du conteneur Netdata..."
    sudo docker run -d --name=netdata \
        -p 19999:19999 \
        -v netdataconfig:/etc/netdata \
        -v netdatalib:/var/lib/netdata \
        -v netdatacache:/var/cache/netdata \
        -v /etc/passwd:/host/etc/passwd:ro \
        -v /etc/group:/host/etc/group:ro \
        -v /proc:/host/proc:ro \
        -v /sys:/host/sys:ro \
        -v /etc/os-release:/host/etc/os-release:ro \
        --cap-add SYS_PTRACE \
        --security-opt apparmor=unconfined \
        netdata/netdata

    echo "(Optionnel) Ouverture du port 19999 dans Firewalld si actif..."
    if systemctl is-active --quiet firewalld; then
        sudo firewall-cmd --zone=docker --add-port=19999/tcp --permanent
        sudo firewall-cmd --reload
    else
        echo "Firewalld non actif, tu dois ouvrir le port 19999 dans les règles de sécurité AWS si nécessaire."
    fi

    echo "Netdata installé. Accès : http://$(hostname -I | awk '{print $1}'):19999"
    echo "Déconnecte puis reconnecte ta session SSH pour que ec2-user puisse lancer Docker sans sudo."
    echo "Appuyez sur une touche pour revenir au menu..."
    read -n 1 -s
}


main() {
    while true; do
        clear
        display_menu
        read -p "Enter your choice: " choice
        case $choice in
            0) set_hostname ;;
            1) raid ;;
            2) unauthshare ;;
            3) webservices ;;
            4) ntp ;;
            5) security ;;
            6) backup ;;
            7) logs ;;
            8) install_netdata ;;
            x) testing ;;
            q|Q) clear && echo "Exiting the web server configuration wizard." && exit ;;
            *) clear && echo "Invalid choice. Please enter a valid option." ;;
        esac
    done
}

main
