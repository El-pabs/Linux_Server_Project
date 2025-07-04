#!/bin/bash

# Vérifier si SELinux est ok
if ! command -v getenforce >/dev/null 2>&1; then
    echo "Installation de SELinux utils"
    sudo dnf install -y policycoreutils selinux-policy selinux-policy-targeted
fi

# statut actuel
echo "Statut actuel de SELinux : $(getenforce)"

# Modifier le fichier de conf si pas déjà enforcing
SELINUX_CONF="/etc/selinux/config"
if grep -q "^SELINUX=disabled" "$SELINUX_CONF"; then
    echo "Activation de SELinux en mode enforcing (redémarrage requis)"
    sudo sed -i 's/^SELINUX=disabled/SELINUX=enforcing/' "$SELINUX_CONF"
    setenforce 1 || echo "Redémarre le système pour appliquer le changement."
elif grep -q "^SELINUX=permissive" "$SELINUX_CONF"; then
    echo "Passage en mode enforcing (immédiat)"
    sudo sed -i 's/^SELINUX=permissive/SELINUX=enforcing/' "$SELINUX_CONF"
    setenforce 1
else
    echo "SELinux est déjà actif en mode enforcing."
fi

# Affiche le statut final
echo "Statut final de SELinux : $(getenforce)"