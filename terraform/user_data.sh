#!/bin/bash
yum update -y
yum install -y docker git

# Start Docker service
systemctl start docker
systemctl enable docker
usermod -a -G docker ec2-user

# Install Docker Compose
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# Install CloudWatch agent
wget https://s3.amazonaws.com/amazoncloudwatch-agent/amazon_linux/amd64/latest/amazon-cloudwatch-agent.rpm
rpm -U ./amazon-cloudwatch-agent.rpm

# Create qavpn user
useradd -m qavpn
usermod -a -G docker qavpn

# Create directories
mkdir -p /opt/qavpn
mkdir -p /var/log/qavpn
chown -R qavpn:qavpn /opt/qavpn
chown -R qavpn:qavpn /var/log/qavpn

# Clone qavpn repository
cd /opt/qavpn
git clone https://github.com/ryan5hanahan/qavpn.git .
chown -R qavpn:qavpn /opt/qavpn

# Build qavpn binary
cd /opt/qavpn
sudo -u qavpn docker build -t qavpn:latest .

# Create systemd service
cat > /etc/systemd/system/qavpn.service << EOF
[Unit]
Description=QAVPN Service
After=docker.service
Requires=docker.service

[Service]
Type=simple
User=qavpn
Group=qavpn
WorkingDirectory=/opt/qavpn
ExecStart=/usr/local/bin/docker-compose up
ExecStop=/usr/local/bin/docker-compose down
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start qavpn service
systemctl daemon-reload
systemctl enable qavpn
systemctl start qavpn

# Configure CloudWatch agent
cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json << EOF
{
    "logs": {
        "logs_collected": {
            "files": {
                "collect_list": [
                    {
                        "file_path": "/var/log/qavpn/*.log",
                        "log_group_name": "/aws/ec2/qavpn",
                        "log_stream_name": "{instance_id}/qavpn.log"
                    }
                ]
            }
        }
    },
    "metrics": {
        "namespace": "QAVPN/EC2",
        "metrics_collected": {
            "cpu": {
                "measurement": [
                    "cpu_usage_idle",
                    "cpu_usage_iowait",
                    "cpu_usage_user",
                    "cpu_usage_system"
                ],
                "metrics_collection_interval": 60
            },
            "disk": {
                "measurement": [
                    "used_percent"
                ],
                "metrics_collection_interval": 60,
                "resources": [
                    "*"
                ]
            },
            "diskio": {
                "measurement": [
                    "io_time"
                ],
                "metrics_collection_interval": 60,
                "resources": [
                    "*"
                ]
            },
            "mem": {
                "measurement": [
                    "mem_used_percent"
                ],
                "metrics_collection_interval": 60
            },
            "netstat": {
                "measurement": [
                    "tcp_established",
                    "tcp_time_wait"
                ],
                "metrics_collection_interval": 60
            },
            "swap": {
                "measurement": [
                    "swap_used_percent"
                ],
                "metrics_collection_interval": 60
            }
        }
    }
}
EOF

# Start CloudWatch agent
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s

# Create health check endpoint
cat > /opt/qavpn/health.sh << 'EOF'
#!/bin/bash
# Simple health check script
if docker ps | grep -q qavpn; then
    echo "OK"
    exit 0
else
    echo "FAIL"
    exit 1
fi
EOF

chmod +x /opt/qavpn/health.sh

# Setup log rotation
cat > /etc/logrotate.d/qavpn << EOF
/var/log/qavpn/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 qavpn qavpn
}
EOF

echo "QAVPN installation completed"
