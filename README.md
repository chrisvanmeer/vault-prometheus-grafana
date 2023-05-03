# Vault / Prometheus / Grafana

This is a small tutorial describing how to get Vault monitored by Prometheus and that allows you to visualize all with Grafana.  
  
In my case, I used 3 MultiPass instances named

1. vault
2. prometheus
3. grafana

These are all running Ubuntu 22.04 so these instructions are for a Debian based distribution.  
By the way, you could also combine all these installations into one instance, but that it not how it works in the field.

## Create MultiPass instances

```bash
# Create cloud-init file
tee custom-cloud-init.yml > /dev/null <<EOF
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
sudo apt update && sudo apt install -y vault jq

# Create config
sudo tee /etc/vault.d/vault.hcl > /dev/null <<EOF
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

# Create log dir
sudo mkdir -p /var/log/vault
sudo chown vault:vault /var/log/vault

# Edit systemd to redirect output to file
sudo sed -i "/^LimitMEMLOCK=.*$/a StandardOutput=append:/var/log/vault.log\nStandardError=append:/var/log/vault.log" /usr/lib/systemd/system/vault.service
sudo systemctl daemon-reload

# Start Vault
sudo systemctl enable --now vault
echo 'export VAULT_ADDR=http://127.0.0.1:8200' >> .bashrc
export VAULT_ADDR=http://127.0.0.1:8200
vault operator init -key-shares=1 -key-threshold=1 > vault.creds
vault operator unseal $(awk '/Unseal/ {print $NF}' vault.creds) >/dev/null
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
vault read -format=json auth/approle/role/prometheus/role-id | jq -r .data.role_id > roleid
vault write -f -format=json auth/approle/role/prometheus/secret-id | jq -r .data.secret_id > secretid
```

## Transfer AppRole files (on localhost)

```bash
scp -3 <vault_ip>:*id <prometheus_ip>:
```

## Install Vault Agent (on `prometheus` instance)

First set an environment variable with the IP address of the `vault` instance.

```bash
# Set Vault server IP
export VAULT_IP=<vault-ip>
```

Then continue with the installation and configuration.

```bash
# Install
sudo apt update && sudo apt install gpg
wget -O- https://apt.releases.hashicorp.com/gpg | gpg --dearmor | sudo tee /usr/share/keyrings/hashicorp-archive-keyring.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install -y vault jq

# Populate agent directory
sudo mkdir -p /opt/vault-agent
cat roleid | sudo tee /opt/vault-agent/roleid > /dev/null
cat secretid | sudo tee /opt/vault-agent/secretid > /dev/null
sudo chown -R vault:vault /opt/vault-agent

# Create config
sudo rm /etc/vault.d/*
sudo tee /etc/vault.d/agent.hcl > /dev/null <<EOF
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
sudo sed -i "s/<vault_ip>/$VAULT_IP/g" /etc/vault.d/agent.hcl

# Systemd
sudo cp /usr/lib/systemd/system/vault.service /usr/lib/systemd/system/vault-agent.service
sudo sed -i 's/server/agent/g' /usr/lib/systemd/system/vault-agent.service
sudo sed -i 's/vault.hcl/agent.hcl/g' /usr/lib/systemd/system/vault-agent.service
sudo sed -i '/Environment/d' /usr/lib/systemd/system/vault-agent.service
sudo sed -i 's/HashiCorp Vault/HashiCorp Vault Agent/g' /usr/lib/systemd/system/vault-agent.service
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
sudo chown -R prometheus:prometheus /var/lib/prometheus
sudo chown -R prometheus:prometheus /etc/prometheus

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
sudo tee /usr/lib/systemd/system/prometheus.service > /dev/null <<EOF
[Unit]
Description=Prometheus
Wants=network-online.target
After=network-online.target

[Service]
User=prometheus
Group=prometheus
Type=simple
ExecStart=/usr/local/bin/prometheus \\
    --config.file /etc/prometheus/prometheus.yml \\
    --storage.tsdb.path /var/lib/prometheus/ \\
    --web.console.templates=/etc/prometheus/consoles \\
    --web.console.libraries=/etc/prometheus/console_libraries

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now prometheus

# Test Prometheus
sudo apt install -y jq
sleep 5
curl http://localhost:9090/api/v1/targets | jq

# Add Vault job
sudo tee -a /etc/prometheus/prometheus.yml > /dev/null <<EOF
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
sleep 5
curl http://localhost:9090/api/v1/targets | jq
```

You should see a job with the label `vault` and after a while, the `status` should be `up`.

## Install Grafana (on `grafana` instance)

```bash# Install
wget -q -O - https://packages.grafana.com/gpg.key | gpg --dearmor | sudo tee /usr/share/keyrings/grafana.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/grafana.gpg] https://packages.grafana.com/oss/deb stable main" | sudo tee -a /etc/apt/sources.list.d/grafana.list
sudo apt update && sudo apt install -y grafana
sudo systemctl enable --now grafana-server
sudo grafana-cli plugins install grafana-piechart-panel
sudo systemctl restart grafana-server
```

1. Log into Grafana on <http://grafana_ip:3000> with `admin/amin`
2. Go to <http://grafana_ip:3000/datasources/new>. Select Prometheus and use <http://prometheus_ip:9090> as the address. Save & Test.
3. Go to <http://grafana_ip:3000/dashboard/import>. Enter ID `12904`, click Load.
4. Select your Prometheus data source in the dropdown and click Import.

## BONUS - Use Promtail and Loki to read log files into Grafana

We can also forward Vault logging to Grafana.  
The components we will use are Loki (the receiver) and Promtail (the sender).  
  
Loki is the receiving end of the log files and we will install that on the `prometheus` instance.    
We will then install Promtail on the `vault` instance.
We are already redirecting the Vault systemd output to a log file (system logs), but we will also enable a Vault audit device to another log file (audit trail).  
So we will configure Promtail to scrape these logs and send them to Loki.
We can then use Grafana to add Loki as a data source and retrieve the logs.

### Part 1 - Install Loki (on instance `prometheus`)

```bash
# Install unzip
sudo apt install -y unzip

# Download Loki
cd /tmp
curl -s https://api.github.com/repos/grafana/loki/releases/latest | grep browser_download_url | grep linux-$(dpkg --print-architecture) | grep -v 'canary\|log\|prom' | cut -d '"' -f 4 | wget -qi -
unzip '*.zip'
rm *.zip
sudo mv loki* /usr/local/bin/loki
sudo mv promtail* /usr/local/bin/promtail
cd

# Loki Configuration
sudo mkdir /etc/loki
sudo tee /etc/loki/loki.yml >/dev/null <<EOF
auth_enabled: false
server:
  http_listen_port: 3100
ingester:
  lifecycler:
    address: 127.0.0.1
    ring:
      kvstore:
        store: inmemory
      replication_factor: 1
    final_sleep: 0s
  chunk_idle_period: 5m
  chunk_retain_period: 30s
  wal:
    enabled: true
    dir: /tmp/wal
schema_config:
  configs:
  - from: 2020-05-15
    store: boltdb
    object_store: filesystem
    schema: v11
    index:
      prefix: index_
      period: 168h
storage_config:
  boltdb:
    directory: /tmp/loki/index
  filesystem:
    directory: /tmp/loki/chunks
limits_config:
  enforce_metric_name: false
  reject_old_samples: true
  reject_old_samples_max_age: 168h
  max_entries_limit_per_query: 500000
analytics:
  reporting_enabled: false
EOF

# Loki Systemd
sudo useradd --no-create-home --shell /bin/false loki
sudo tee /etc/systemd/system/loki.service >/dev/null <<EOF
[Unit]
Description=Loki service
After=network.target

[Service]
Type=simple
User=loki
ExecStart=/usr/local/bin/loki -config.file /etc/loki/loki.yml

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now loki
```

### Part 2 - Enable audit logging and install Promtail (on instance `vault`)

First we need to specify the IP address of the Prometheus instance.

```bash
export PROMETHEUS_IP=<prometheus_ip>
```

Then continue the installation.

```bash
# Enable Vault audit devices
vault audit enable file file_path=/var/log/vault/vault-audit.log mode=0644
vault audit enable syslog

# Install unzip
sudo apt install -y unzip

# Download Promtail
cd /tmp
curl -s https://api.github.com/repos/grafana/loki/releases/latest | grep browser_download_url | grep linux-$(dpkg --print-architecture) | grep prom | cut -d '"' -f 4 | wget -qi -
unzip '*.zip'
rm *.zip
sudo mv promtail* /usr/local/bin/promtail
cd

# Promtail configuration
sudo mkdir /etc/promtail
sudo tee /etc/promtail/promtail.yml >/dev/null <<EOF
server:
  http_listen_port: 9080
  grpc_listen_port: 0
positions:
  filename: /tmp/positions.yaml
clients:
  - url: http://<prometheus_ip>:3100/loki/api/v1/push
scrape_configs:
  - job_name: vault_audit_logs
    static_configs:
    - targets:
        - localhost
      labels:
        job: vault-auditlogs
        __path__: /var/log/vault/vault-audit.log
  - job_name: vault_system_operational_logs
    static_configs:
    - targets:
        - localhost
      labels:
        job: vault-systemlogs
        __path__: /var/log/vault/vault.log
EOF
sudo sed -i "s/<prometheus_ip>/$PROMETHEUS_IP/g" /etc/promtail/promtail.yml

# Promtail Systemd
sudo useradd --no-create-home --shell /bin/false promtail
sudo tee /etc/systemd/system/promtail.service >/dev/null <<EOF
[Unit]
Description=Promtail service
After=network.target

[Service]
Type=simple
User=promtail
ExecStart=/usr/local/bin/promtail -config.file /etc/promtail/promtail.yml

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now promtail
```

You can then go to the Grafana UI and add a new datasource *Loki* with a <http://prometheus_ip:3100> address.  
Then you can go to Explore and enter the following query to get you started.

For the system logs:
```
{job="vault-systemlogs"}
```

For the audit logs:
```
{job="vault-auditlogs"}
```
