

# 🐧 Projet Linux – Serveur Multi-Services Automatisé (RAID 1, Amazon Linux 2023)

> Projet de fin de cycle - Bachelier Informatique & Systèmes  
> Finalité Télécommunications & Réseaux - HEH Mons 2024-2025

---

## 🚀 Objectif du projet

Ce projet vise à automatiser l’installation, la configuration et la sécurisation d’un serveur Linux multi-services sur AWS, en respectant le [cahier des charges officiel](cdc.pdf).  
L’ensemble des opérations est centralisé dans le script interactif **installGlobal.sh**.

---

## 🗂️ Structure du projet

```
.
├── cdc.pdf                # Cahier des charges officiel
├── README.md
└── scripts/
    ├── Fail2Ban_Alone.sh
    ├── dns.sh
    ├── dns2.sh
    ├── install.sh
    ├── install2.sh
    ├── installGlobal.sh   # Script principal tout-en-un
    ├── setup_netdata_docker.sh
    └── test.sh
```

---

## 🧩 Fonctionnalités principales

- **RAID 1 logiciel** (mirroring) avec LVM : partitionnement automatique pour la fiabilité des données.
- **Partage de fichiers multiplateforme** :
  - NFS (Linux) et Samba (Windows) sans authentification.
  - Quotas sur le partage public.
- **Hébergement web multi-client** :
  - Création automatisée de domaines internes (DNS maître + zone inverse).
  - Déploiement Apache/PHP, VirtualHosts, certificats SSL auto-signés.
  - Base de données MariaDB dédiée par client.
  - Accès FTP et Samba privé au dossier web.
- **Gestion des utilisateurs web** : ajout/suppression automatisée, droits personnalisés.
- **Sécurisation avancée** :
  - FirewallD, SELinux, Fail2Ban (SSH/FTP), logs centralisés.
- **Sauvegardes automatisées** : script rsync + dump SQL, planification via systemd timer.
- **Monitoring web** : installation et accès à Netdata (via Docker).
- **Serveur NTP** : synchronisation horaire réseau.

---

## 🛠️ Technologies utilisées

| Composant           | Version / Outil                    |
|---------------------|------------------------------------|
| OS                  | Amazon Linux 2023                  |
| RAID                | mdadm (RAID 1) + LVM               |
| Partage fichiers    | NFS, Samba                         |
| Web                 | Apache 2.4, PHP, Certificats SSL   |
| Base de données     | MariaDB, phpMyAdmin                |
| DNS                 | Bind9 (zone directe et inverse)    |
| FTP                 | vsftpd                             |
| Monitoring          | Netdata (via Docker)               |
| Sécurité            | Firewalld, SELinux, Fail2Ban       |
| Sauvegarde          | rsync, mysqldump, systemd timer    |

---

## ⚡ Installation & utilisation

### 1. Prérequis

- Amazon Linux 2023 (AMI officielle AWS)
- 2 disques pour le RAID 1 (ex : `/dev/xvdb`, `/dev/xvdc`)
- Droits root/sudo

### 2. Cloner et lancer le script

```bash
git clone https://github.com/El-pabs/Linux_Server_Project.git
cd scripts
chmod +x installGlobal.sh
sudo ./installGlobal.sh
```

### 3. Menu interactif

Lancez le script et naviguez dans le menu :

```
| 0. Set server hostname
| 1. RAID Configuration
| 2. NFS (partage sans authentification)
| 3. Web services management (DNS, web, DB, FTP)
| 4. NTP Time Server
| 5. Install fail2ban (sécurité)
| 6. Backup (sauvegarde automatisée)
| 7. Consult Logs Dashboard
| 8. Installer Netdata (monitoring)
| q. Quit
```

---

## 🗃️ Exemples d’utilisation

- **RAID 1** : créez un volume miroir sécurisé pour vos données.
- **Ajout d’un client web** :  
  - Génère le VirtualHost, le DNS, la base MariaDB, le partage Samba/FTP, le certificat SSL et l’index PHP.
- **Partage public** : activez un dossier partagé accessible sans authentification sous Linux et Windows.
- **Sauvegarde** : planifiez un backup automatique (fichiers + bases SQL) toutes les 1h58 sur le volume RAID.
- **Logs** : dashboard CLI pour consulter les logs Apache, Samba, SSH, Fail2Ban et système.
- **Monitoring** : accédez à Netdata via navigateur (`http://:19999`).

---

## 🔒 Sécurité intégrée

- **FirewallD** pré-configuré (HTTP, HTTPS, FTP, Samba, DNS, NFS)
- **SELinux** activé et contextes adaptés
- **Fail2Ban** prêt à l’emploi (SSH, FTP, IPs admin whitelistées)
- **Quotas disque** sur le partage public
- **Accès root SSH désactivé** (à activer manuellement si besoin)

---

## 📑 Documentation

- **Script commenté** : chaque fonction est documentée dans le code.


---

## 👨‍💻 Auteurs

- Robin Gillard
- Aimerik Gustin

HEH Mons – Projets Linux 2024-2025

---

> Pour toute question ou suggestion, ouvrez une issue sur ce dépôt ou contactez-nous.
