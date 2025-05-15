#!/bin/bash

echo "=== TESTS AUTOMATIQUES DES SERVICES ==="

# 1. Test Hostname
echo -n "Hostname actuel : "
hostnamectl --static

# 2. Test RAID
echo "Vérification RAID (mdadm)..."
if cat /proc/mdstat | grep -q 'md'; then
    echo "RAID détecté :"
    cat /proc/mdstat
else
    echo "Aucun RAID détecté."
fi

# 3. Test NFS
echo "Vérification NFS..."
systemctl is-active --quiet nfs-server && echo "NFS actif" || echo "NFS inactif"
exportfs -v

# 4. Test Samba
echo "Vérification Samba..."
systemctl is-active --quiet smb && echo "Samba actif" || echo "Samba inactif"
testparm -s | grep -E "unauth_share|public"

# 5. Test Apache/PHP
echo "Vérification Apache..."
systemctl is-active --quiet httpd && echo "Apache actif" || echo "Apache inactif"
echo "Fichiers VirtualHost présents :"
ls /etc/httpd/conf.d/*.conf 2>/dev/null

# 6. Test MariaDB
echo "Vérification MariaDB..."
systemctl is-active --quiet mariadb && echo "MariaDB actif" || echo "MariaDB inactif"

# 7. Test FTP (vsftpd)
echo "Vérification vsftpd..."
systemctl is-active --quiet vsftpd && echo "vsftpd actif" || echo "vsftpd inactif"

# 8. Test Fail2Ban service
echo "Vérification Fail2Ban..."
systemctl is-active --quiet fail2ban && echo "Fail2Ban actif" || echo "Fail2Ban inactif"
echo "Jails Fail2Ban configurés et leur statut :"
# Liste tous les jails et leur status détaillé
JAILS=$(sudo fail2ban-client status | grep "Jail list" | sed -E 's/^[^:]+:[ \t]+//' | tr ',' ' ')
for JAIL in $JAILS; do
    echo "----- Jail: $JAIL -----"
    sudo fail2ban-client status "$JAIL"
    echo ""
done

# 9. Test Chrony (NTP)
echo "Vérification Chrony..."
systemctl is-active --quiet chronyd && echo "Chrony actif" || echo "Chrony inactif"
chronyc tracking

# 10. Test Backup Timer
echo "Vérification du timer de backup..."
systemctl is-enabled --quiet backup.timer && echo "Timer backup activé" || echo "Timer backup non activé"
systemctl status backup.timer

# 11. Test Netdata
echo "Vérification Netdata (Docker)..."
docker ps | grep netdata && echo "Netdata container actif" || echo "Netdata non trouvé"

echo "=== FIN DES TESTS ==="
