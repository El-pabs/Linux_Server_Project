#!/bin/bash

echo "Installing Fail2Ban..."

# Check if Fail2Ban is already installed
if ! command -v fail2ban-server &> /dev/null; then
    sudo dnf install -y fail2ban || { echo "Failed to install Fail2Ban. Exiting."; exit 1; }
else
    echo "Fail2Ban is already installed."
fi

# Enable and start the Fail2Ban service
sudo systemctl enable fail2ban || { echo "Failed to enable Fail2Ban. Exiting."; exit 1; }
sudo systemctl start fail2ban || { echo "Failed to start Fail2Ban. Exiting."; exit 1; }

# Create the configuration directory if necessary
sudo mkdir -p /etc/fail2ban/jail.d

# Configure Fail2Ban to protect the SSH service
# Configure Fail2Ban to protect the SSH service
cat <<EOF | sudo tee /etc/fail2ban/jail.d/sshd.local > /dev/null
[sshd]
enabled = true
port = 22
action = %(action_mwl)s
logpath = %(sshd_log)s
maxretry = 3
bantime = 600
findtime = 600
EOF

# Configure Fail2Ban to protect the FTP service
cat <<EOF | sudo tee /etc/fail2ban/jail.d/vsftpd.local > /dev/null
[vsftpd]
enabled = true
port = 21
action = %(action_mwl)s
logpath = /var/log/vsftpd.log
maxretry = 3
bantime = 600
findtime = 600
EOF

# Add IPs to whitelist
# Whitelist IP admin SSH
echo "ignoreip = 192.168.42.2" | sudo tee -a /etc/fail2ban/jail.d/sshd.local > /dev/null

# Whitelist IP admin FTP
echo "ignoreip = 192.168.1.101" | sudo tee -a /etc/fail2ban/jail.d/vsftpd.local > /dev/null


# Restart Fail2Ban to apply the changes
sudo systemctl restart fail2ban || { echo "Failed to restart Fail2Ban. Exiting."; exit 1; }

echo "Fail2Ban installed and configured successfully."
