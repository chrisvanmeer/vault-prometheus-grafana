# Vault / Prometheus / Grafana

This is a small tutorial describing how to get Vault monitored by Prometheus and that allows you to visualize all with Grafana.  
  
In my case, I used 3 MultiPass instances named

1. vault
2. prometheus
3. grafana

These are all running Ubuntu 22.04 so these instructions are for a Debian based distribution.

## Create MultiPass instances

```bash
# Create cloud-init file
cat > custom-cloud-init.yml -<< EOF
users:
  - default
  - name: <user>
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - <ssh_key>
EOF
sed -i "s/<user>/$(whoami)/g" custom-cloud-init.yml
sed -i "s%<ssh_key>%$(cat ~/.ssh/id_rsa.pub)%g" custom-cloud-init.yml

# Create instances
multipass launch --name vault --cloud-init custom-cloud-init.yml jammy
multipass launch --name prometheus --cloud-init custom-cloud-init.yml jammy
multipass launch --name grafana --cloud-init custom-cloud-init.yml jammy

# Get the instance details
multipass list
```

Now you should be able to SSH into the created machines by using their IP adresses.

## Install Vault Server (on `vault` instance)

```bash
# Install
sudo apt update && sudo apt install gpg
wget -O- https://apt.releases.hashicorp.com/gpg | gpg --dearmor | sudo tee /usr/share/keyrings/hashicorp-archive-keyring.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install vault jq

# Create config
sudo tee /etc/vault.d/vault.hcl > /dev/null -<<EOF
ui           = true
api_addr     = "http://<ip>:8200"
cluster_addr = "http://<ip>:8201"

storage "raft" {
  node_id = "vault"
  path    = "/opt/vault/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1
}

telemetry {
  disable_hostname          = true
  prometheus_retention_time = "12h"
}
EOF
sudo sed -i "s/<ip>/$(hostname -I | cut -d ' ' -f1)/g" /etc/vault.d/vault.hcl

# Start Vault
sudo systemctl enable --now vault
echo 'export VAULT_ADDR=http://127.0.0.1:8200' >> .bashrc
export VAULT_ADDR=http://127.0.0.1:8200
vault status
vault operator init -key-shares=1 -key-threshold=1 > vault.creds
vault operator unseal $(awk '/Unseal/ {print $NF}' vault.creds)
vault login -no-print $(awk '/Root/ {print $NF}' vault.creds)
vault -autocomplete-install
source ~/.bashrc

# Policies
vault policy write pol-renew -<<EOF
path "auth/token/create" {
  capabilities = [ "update" ]
}
EOF

vault policy write pol-prometheus-metrics -<<EOF
path "sys/metrics" {
  capabilities = [ "read" ]
}
EOF

# AppRole
vault auth enable approle
vault write auth/approle/role/prometheus policies="pol-renew,pol-prometheus-metrics"
vault read -format=json auth/approle/role/prometheus/role-id | jq -r .data.role_id
vault write -f -format=json auth/approle/role/prometheus/secret-id | jq -r .data.secret_id
```

## Install Vault Agent (on `prometheus` instance)

```bash
# Install
sudo apt update && sudo apt install gpg
wget -O- https://apt.releases.hashicorp.com/gpg | gpg --dearmor | sudo tee /usr/share/keyrings/hashicorp-archive-keyring.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install vault jq

# Set Vault server IP
export VAULT_IP=<vault-ip>

# Create directory
sudo mkdir -p /opt/vault-agent

# Copy the roleid from the AppRole output to the correct file
sudo echo "<roleid>" > /opt/vault-agent/roleid

# Copy the secretid from the AppRole output to the correct file
sudo echo "<secretid>" > /opt/vault-agent/secretid

# Set ownership
sudo chown -R vault:vault /opt/vault-agent

# Create config
sudo rm /etc/vault.d/*
sudo tee /etc/vault.d/agent.hcl > /dev/null -<<EOF
pid_file = "/opt/vault-agent/pidfile"

auto_auth {
  method "approle" {
    mount_path = "auth/approle"
    config = {
      role_id_file_path   = "/opt/vault-agent/roleid"
      secret_id_file_path = "/opt/vault-agent/secretid"
    }
  }
  sink "file" {
    config = {
      path = "/opt/vault-agent/token"
      mode = 0644
    }
  }
}

listener "tcp" {
  address     = "127.0.0.1:8007"
  tls_disable = true
}

vault {
  address     = "http://<vault_ip>:8200"
  tls_disable = true
}
EOF
sudo sed -i "s/<vault_ip>/$VAULT_IP/g" /etc/vault.d/agent.yml

# Systemd
sudo cp /usr/lib/systemd/system/vault.service /usr/lib/systemd/system/vault-agent.service
sudo sed -i 's/agent/server/g' vault-agent.service
sudo sed -i 's/vault.hcl/agent.hcl/g' vault-agent.service
sudo sed -i '/Environment/d' vault-agent.service
sudo sed -i 's/HashiCorp Vault/HashiCorp Vault Agent/g' vault-agent.service
sudo systemctl daemon-reload
sudo systemctl enable --now vault-agent
```

You should now see a file named `token` in `/opt/vault-agent` and see the `secretid` file deleted from that same directory. 

## Install Prometheus (on `prometheus` instance)

```bash
# Add user
sudo groupadd --system prometheus
sudo useradd -s /sbin/nologin --system -g prometheus prometheus

# Create directories
sudo mkdir /var/lib/prometheus
for i in rules rules.d files_sd; do sudo mkdir -p /etc/prometheus/${i}; done
chown -R prometheus:prometheus /var/lib/prometheus
chown -R prometheus:prometheus /etc/prometheus

# Download Prometheus
cd /tmp
curl -s https://api.github.com/repos/prometheus/prometheus/releases/latest | grep browser_download_url | grep linux-$(dpkg --print-architecture) | cut -d '"' -f 4 | wget -qi -
tar xvf prometheus*.tar.gz
cd prometheus*/

# Move files
sudo mv prometheus promtool /usr/local/bin/
sudo mv prometheus.yml /etc/prometheus/prometheus.yml
sudo mv consoles/ console_libraries/ /etc/prometheus/
cd

# Systemd unit
sudo tee /usr/lib/systemd/system/prometheus.service > /dev/null -<<EOF
[Unit]
Description=Prometheus
Wants=network-online.target
After=network-online.target

[Service]
User=prometheus
Group=prometheus
Type=simple
ExecStart=/usr/local/bin/prometheus \
    --config.file /etc/prometheus/prometheus.yml \
    --storage.tsdb.path /var/lib/prometheus/ \
    --web.console.templates=/etc/prometheus/consoles \
    --web.console.libraries=/etc/prometheus/console_libraries

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now prometheus

# Test Prometheus
sudo apt install -y jq
curl http://localhost:9090/api/v1/targets | jq

# Add Vault job
sudo tee -a /etc/prometheus/prometheus.yml > /dev/null -<<EOF
  - job_name: 'vault'
    static_configs:
      - targets: ['<vault_ip>:8200']
    metrics_path: /v1/sys/metrics
    params:
      format: ['prometheus']
    scheme: http
    authorization:
      credentials_file: /opt/vault-agent/token
EOF
sudo sed -i "s/<vault_ip>/$VAULT_IP/g" /etc/prometheus/prometheus.yml
sudo systemctl restart prometheus

# Test again
curl http://localhost:9090/api/v1/targets | jq
```

## Install Grafana (on `grafana` instance)

```bash
# Install
wget -q -O - https://packages.grafana.com/gpg.key | gpg --dearmor | sudo tee /usr/share/keyrings/grafana.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/grafana.gpg] https://packages.grafana.com/oss/deb stable main" | sudo tee -a /etc/apt/sources.list.d/grafana.list
sudo apt update
sudo apt install grafana
sudo systemctl enable --now grafana-server

# Configure
sudo grafana-cli admin reset-admin-password vault
```

1. Log into Grafana on <http://grafana_ip:3000> with `admin/vault`
2. Go to <http://grafana_ip:3000/datasources/new>. Select Prometheus and use <http://prometheus_ip:9090> as the address. Save & Test.
3. Go to <http://grafana_ip:3000/dashboard/import>. Enter ID `12904`, click Load.
4. Select your Prometheus data source in the dropdown and click Import.
