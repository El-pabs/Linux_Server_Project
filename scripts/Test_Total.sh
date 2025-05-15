#!/bin/bash

# Couleurs pour une meilleure lisibilité
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonction pour les en-têtes de section
print_header() {
    echo -e "\n${BLUE}======== $1 ========${NC}"
}

# Fonction pour afficher le statut d'un service
check_service() {
    local service=$1
    local display_name=$2
    if systemctl is-active --quiet "$service"; then
        echo -e "  ${GREEN}✅ $display_name est actif${NC}"
        return 0
    else
        echo -e "  ${RED}❌ $display_name est inactif${NC}"
        return 1
    fi
}

# Fonction pour tester un port
check_port() {
    local port=$1
    local service_name=$2
    if nc -z localhost "$port" 2>/dev/null || ss -tuln | grep -q ":$port "; then
        echo -e "  ${GREEN}✅ Port $port ($service_name) est ouvert${NC}"
        return 0
    else
        echo -e "  ${RED}❌ Port $port ($service_name) n'est pas ouvert${NC}"
        return 1
    fi
}

clear
echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}===== RAPPORT DE VÉRIFICATION DU SYSTÈME =======${NC}"
echo -e "${BLUE}================================================${NC}"
echo -e "Date: $(date)"
echo -e "Hostname: $(hostname)"

# 1. Test Hostname
print_header "CONFIGURATION DU HOSTNAME"
echo -e "  Hostname actuel : $(hostnamectl --static)"
echo -e "  FQDN : $(hostname -f)"

# 2. Test Firewall
print_header "FIREWALL"
check_service "firewalld" "Firewall"
if systemctl is-active --quiet firewalld; then
    echo -e "\n  Services autorisés par le firewall:"
    firewall-cmd --list-services | sed 's/ /\n  - /g' | sed 's/^/  - /' | grep -v "^  - $"
    
    echo -e "\n  Ports autorisés par le firewall:"
    firewall-cmd --list-ports | sed 's/ /\n  - /g' | sed 's/^/  - /' | grep -v "^  - $"
fi

# 3. Test RAID
print_header "SYSTEME RAID"
if cat /proc/mdstat 2>/dev/null | grep -q 'md'; then
    echo -e "  ${GREEN}✅ RAID configuré${NC}"
    echo -e "\n  Détails des dispositifs RAID:"
    cat /proc/mdstat | grep -E 'md|blocks'
    
    # Vérifier l'état de chaque dispositif RAID
    for md in $(cat /proc/mdstat | grep ^md | cut -d : -f 1); do
        echo -e "\n  Détails pour $md:"
        mdadm --detail /dev/$md | grep -E "State :|Active Devices :|Working Devices :|Failed Devices :|Spare Devices :"
    done
else
    echo -e "  ${YELLOW}⚠️ Aucun RAID détecté${NC}"
fi

# 4. Test Partages Réseau
print_header "PARTAGES RÉSEAU"

# 4.1 Test NFS
echo -e "${YELLOW}NFS:${NC}"
check_service "nfs-server" "Service NFS"
if systemctl is-active --quiet nfs-server; then
    echo -e "\n  Partages NFS exportés:"
    if exportfs -v | grep -v "^$"; then
        exportfs -v
    else
        echo -e "  ${YELLOW}⚠️ Aucun partage NFS configuré${NC}"
    fi
    
    # Vérifier que les principaux services RPC nécessaires sont en cours d'exécution
    echo -e "\n  Services RPC nécessaires:"
    rpcinfo -p localhost | grep -E "nfs|mountd"
fi

# 4.2 Test Samba
echo -e "\n${YELLOW}Samba:${NC}"
check_service "smb" "Service Samba"
if systemctl is-active --quiet smb; then
    echo -e "\n  Partages Samba configurés:"
    testparm -s --suppress-prompt 2>/dev/null | grep -A 1 "\[" | grep -v "\--" | sed '/^$/d'
fi

# 5. Test Serveur Web
print_header "SERVICES WEB"

# 5.1 Test Apache
echo -e "${YELLOW}Apache:${NC}"
check_service "httpd" "Serveur Apache"
check_port "80" "HTTP"
check_port "443" "HTTPS"

if systemctl is-active --quiet httpd; then
    echo -e "\n  Sites web configurés:"
    ls /etc/httpd/conf.d/*.conf 2>/dev/null | while read conf; do
        servername=$(grep -i "ServerName" $conf 2>/dev/null | head -1 | awk '{print $2}')
        if [ -n "$servername" ]; then
            echo -e "  - $servername ($(basename $conf))"
        fi
    done
    
    # Test de la version de PHP
    if command -v php >/dev/null 2>&1; then
        echo -e "\n  ${GREEN}✅ PHP installé:${NC} $(php -v | head -1 | cut -d '(' -f1)"
        
        # Vérifier extension MySQL
        if php -m | grep -q -E "mysqli|pdo_mysql"; then
            echo -e "  ${GREEN}✅ Support MySQL dans PHP${NC}"
        else
            echo -e "  ${RED}❌ Support MySQL non configuré dans PHP${NC}"
        fi
    fi
    
    # Test phpMyAdmin
    if [ -d "/var/www/html/phpMyAdmin" ] || [ -d "/usr/share/phpMyAdmin" ]; then
        echo -e "  ${GREEN}✅ phpMyAdmin installé${NC}"
    fi
fi

# 5.2 Test Base de Données
echo -e "\n${YELLOW}MariaDB:${NC}"
check_service "mariadb" "Serveur MariaDB"
if systemctl is-active --quiet mariadb; then
    if command -v mysqladmin >/dev/null 2>&1; then
        if mysqladmin ping 2>/dev/null; then
            echo -e "  ${GREEN}✅ MariaDB répond aux requêtes${NC}"
        else
            echo -e "  ${RED}❌ MariaDB ne répond pas aux requêtes${NC}"
        fi
    fi
fi

# 6. Test DNS (Bind)
print_header "SERVEUR DNS"
check_service "named" "Serveur DNS (Named/Bind)"
check_port "53" "DNS"

if systemctl is-active --quiet named; then
    echo -e "\n  Zones DNS configurées:"
    if [ -f /etc/named.conf ]; then
        grep -E "zone\s+\".*\"" /etc/named.conf | grep -v "localhost" | grep -v "in-addr.arpa"
    fi
fi

# 7. Test NTP (Chrony)
print_header "SYNCHRONISATION HORAIRE (NTP)"
check_service "chronyd" "Service Chrony"

if systemctl is-active --quiet chronyd; then
    echo -e "\n  Statut de synchronisation:"
    chronyc tracking | head -2
    
    echo -e "\n  Sources NTP:"
    chronyc sources | head -4
fi

# 8. Test FTP (vsftpd)
print_header "SERVEUR FTP"
check_service "vsftpd" "Service FTP"
check_port "21" "FTP"

if systemctl is-active --quiet vsftpd; then
    echo -e "\n  Configuration FTP:"
    
    if grep -q "^anonymous_enable=YES" /etc/vsftpd/vsftpd.conf 2>/dev/null; then
        echo -e "  ${YELLOW}⚠️ FTP anonyme activé${NC}"
    else
        echo -e "  ${GREEN}✅ FTP anonyme désactivé${NC}"
    fi
    
    if grep -q "^ssl_enable=YES" /etc/vsftpd/vsftpd.conf 2>/dev/null; then
        echo -e "  ${GREEN}✅ FTPS (FTP over SSL) activé${NC}"
    fi
fi

# 9. Test Sécurité
print_header "SÉCURITÉ"

# 9.1 Test Fail2Ban
echo -e "${YELLOW}Fail2Ban:${NC}"
check_service "fail2ban" "Service Fail2Ban"

if systemctl is-active --quiet fail2ban; then
    echo -e "\n  Jails Fail2Ban configurés:"
    fail2ban-client status 2>/dev/null | grep "Jail list" | sed -E 's/^[^:]+:[ \t]+//'
    
    # Afficher un exemple de jail spécifique
    if fail2ban-client status sshd >/dev/null 2>&1; then
        echo -e "\n  Détails du jail SSH:"
        fail2ban-client status sshd | grep "Currently banned" 
    fi
fi

# 9.2 Test SELinux
echo -e "\n${YELLOW}SELinux:${NC}"
if command -v getenforce >/dev/null 2>&1; then
    selinux_status=$(getenforce)
    if [ "$selinux_status" == "Enforcing" ]; then
        echo -e "  ${GREEN}✅ SELinux est actif en mode Enforcing${NC}"
    elif [ "$selinux_status" == "Permissive" ]; then
        echo -e "  ${YELLOW}⚠️ SELinux est en mode Permissive${NC}"
    else
        echo -e "  ${RED}❌ SELinux est désactivé${NC}"
    fi
fi

# 9.3 Test ClamAV
echo -e "\n${YELLOW}ClamAV:${NC}"
if command -v clamscan >/dev/null 2>&1; then
    echo -e "  ${GREEN}✅ ClamAV est installé:${NC} $(clamscan --version)"
    
    # Vérifier si les scans périodiques sont configurés
    if grep -q clamscan /etc/crontab 2>/dev/null; then
        echo -e "  ${GREEN}✅ Scan ClamAV périodique configuré${NC}"
    fi
fi

# 10. Test Surveillance inotify
print_header "SURVEILLANCE SYSTÈME"
if [ -f /etc/systemd/system/inotify-monitor.service ]; then
    if systemctl is-active --quiet inotify-monitor; then
        echo -e "  ${GREEN}✅ Service de surveillance iNotify actif${NC}"
        
        # Vérifier le fichier log
        if [ -f /var/log/inotify_monitor.log ]; then
            echo -e "  ${GREEN}✅ Journal de surveillance configuré${NC}"
        fi
    fi
else
    echo -e "  ${YELLOW}⚠️ Service de surveillance iNotify non configuré${NC}"
fi

# 11. Test Backup
print_header "SAUVEGARDE"
if systemctl list-unit-files | grep -q backup.timer; then
    if systemctl is-active --quiet backup.timer; then
        echo -e "  ${GREEN}✅ Timer de backup actif${NC}"
        echo -e "  Prochain déclenchement: $(systemctl show backup.timer | grep NextElapseUSecRealtime | cut -d= -f2)"
    else
        echo -e "  ${RED}❌ Timer de backup inactif${NC}"
    fi
    
    # Vérifier le script de backup
    if [ -f /usr/local/bin/auto_backup.sh ]; then
        echo -e "  ${GREEN}✅ Script de backup trouvé${NC}"
    fi
else
    echo -e "  ${RED}❌ Timer de backup non configuré${NC}"
fi

# 12. Test Monitoring (Netdata)
print_header "MONITORING NETDATA"
if command -v docker >/dev/null 2>&1; then
    if docker ps 2>/dev/null | grep -q netdata; then
        echo -e "  ${GREEN}✅ Container Netdata en cours d'exécution${NC}"
        container_id=$(docker ps | grep netdata | awk '{print $1}')
        port=$(docker port $container_id 2>/dev/null | grep -i tcp | head -1 | cut -d ":" -f2)
        
        if [ -n "$port" ]; then
            ip_addr=$(hostname -I | awk '{print $1}')
            echo -e "  Interface web disponible sur: http://$ip_addr:$port"
        fi
    else
        echo -e "  ${RED}❌ Container Netdata non trouvé${NC}"
    fi
else
    echo -e "  ${RED}❌ Docker n'est pas installé${NC}"
fi

# Résumé final
print_header "RÉSUMÉ GLOBAL DES SERVICES"

services=(
    "firewalld:Firewall" 
    "httpd:Serveur Web (Apache)" 
    "mariadb:Base de données (MariaDB)" 
    "named:Serveur DNS (Bind)" 
    "chronyd:Synchronisation NTP" 
    "nfs-server:Partage NFS" 
    "smb:Partage Samba" 
    "vsftpd:Serveur FTP" 
    "fail2ban:Protection Fail2Ban"
)

for svc in "${services[@]}"; do
    name="${svc#*:}"
    service="${svc%:*}"
    if systemctl is-active --quiet "$service"; then
        echo -e "  ${GREEN}✅ $name${NC}"
    else
        echo -e "  ${RED}❌ $name${NC}"
    fi
done

# État SELinux
if command -v getenforce >/dev/null 2>&1; then
    selinux_status=$(getenforce)
    if [ "$selinux_status" == "Enforcing" ]; then
        echo -e "  ${GREEN}✅ SELinux (Mode Enforcing)${NC}"
    elif [ "$selinux_status" == "Permissive" ]; then
        echo -e "  ${YELLOW}⚠️ SELinux (Mode Permissive)${NC}"
    else
        echo -e "  ${RED}❌ SELinux (Désactivé)${NC}"
    fi
fi

# Vérifier si RAID est configuré correctement
if cat /proc/mdstat 2>/dev/null | grep -q 'md'; then
    if cat /proc/mdstat | grep -q "\[[_U]*_\]"; then
        echo -e "  ${RED}❌ RAID (Problème détecté)${NC}"
    else
        echo -e "  ${GREEN}✅ RAID (Fonctionnel)${NC}"
    fi
fi

echo -e "\n${BLUE}================================================${NC}"
echo -e "${BLUE}================== FIN DU RAPPORT ================${NC}"
echo -e "${BLUE}================================================${NC}"
