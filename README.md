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
sed -i'' -e "s/<user>/$(whoami)/g" custom-cloud-init.yml
sed -i'' -e "s%<ssh_key>%$(cat ~/.ssh/id_rsa.pub)%g" custom-cloud-init.yml

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
## Install Promtail (on instance `vault`)

We will export the logs to Loki, which will be running on `grafana` instance.  
So first we will have to specify that IP address.

```bash
export GRAFANA_IP=<grafana_ip>
```

Then continue with the installation.

```bash
# Install unzip
sudo apt install -y unzip

# Download promtail
cd /tmp
curl -s https://api.github.com/repos/grafana/loki/releases/latest | grep browser_download_url | grep linux-$(dpkg --print-architecture) | grep -v 'canary\|log\|loki' | cut -d '"' -f 4 | wget -qi -
unzip '*.zip'
rm *.zip
sudo mv promtail* /usr/local/bin/promtail
cd

# Configuration
sudo mkdir /etc/promtail
sudo tee /etc/promtail/promtail.yml >/dev/null <<EOF
server:
  http_listen_port: 9080
  grpc_listen_port: 0
positions:
  filename: /tmp/positions.yaml
clients:
  - url: http://<grafana_ip>:3100/loki/api/v1/push
scrape_configs:
  - job_name: syslog
    syslog:
      listen_address: 0.0.0.0:1514
      labels:
        job: syslog
    relabel_configs:
      - source_labels: [__syslog_message_hostname]
        target_label: host
      - source_labels: [__syslog_message_hostname]
        target_label: hostname
      - source_labels: [__syslog_message_severity]
        target_label: level
      - source_labels: [__syslog_message_app_name]
        target_label: application
      - source_labels: [__syslog_message_facility]
        target_label: facility
      - source_labels: [__syslog_connection_hostname]
        target_label: connection_hostname
EOF
sudo sed -i "s/<grafana_ip>/$GRAFANA_IP/g" /etc/promtail/promtail.yml

# Systemd
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

# Syslog forwarding
sudo apt install -y rsyslog
sudo tee /etc/rsyslog.d/promtail.conf >/dev/null <<EOF
*.* action(type="omfwd" protocol="tcp" target="127.0.0.1" port="1514" Template="RSYSLOG_SyslogProtocol23Format" TCP_Framing="octet-counted" KeepAlive="on")
EOF
sudo systemctl enable --now rsyslog

# Enable Vault audit
vault audit enable syslog
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

## Install Loki (on instance `grafana`)

```bash
# Install unzip
sudo apt install -y unzip

# Download loki
cd /tmp
curl -s https://api.github.com/repos/grafana/loki/releases/latest | grep browser_download_url | grep linux-$(dpkg --print-architecture) | grep -v 'canary\|log\|promtail' | cut -d '"' -f 4 | wget -qi -
unzip '*.zip'
rm *.zip
sudo mv loki* /usr/local/bin/loki
cd

# Configuration
sudo mkdir /etc/loki
sudo tee /etc/loki/loki.yml >/dev/null <<EOF
auth_enabled: false
server:
  http_listen_port: 3100
ingester:
  lifecycler:
    address: 0.0.0.0
    ring:
      kvstore:
        store: inmemory
      replication_factor: 1
    final_sleep: 0s
  chunk_idle_period: 5m
  chunk_retain_period: 30s
  wal:
    enabled: false
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

# Systemd
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

You can then go to the Grafana UI and add a new datasource *Loki* with a <http://localhost:3100> address.  
Then you can go to Explore and enter the following query to get you started:

```
{application="vault"} | json type="request" | json display_name!="approle" | __error__=``
```
