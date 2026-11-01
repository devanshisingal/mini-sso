# ==============================================================================
# Mini SSO AWS Infrastructure (Terraform)
# ==============================================================================

# 1. Base Networking (VPC, Subnet, Gateway)
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "mini-sso-vpc"
  }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "mini-sso-igw"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "${var.aws_region}a"

  tags = {
    Name = "mini-sso-public-subnet"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }

  tags = {
    Name = "mini-sso-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# 2. Security Group Hardening
resource "aws_security_group" "web" {
  name        = "mini-sso-sg"
  description = "Allow inbound HTTPS/HTTP and administrative SSH"
  vpc_id      = aws_vpc.main.id

  # HTTPS Ingress
  ingress {
    description = "TLS inbound for SSO IdP and Demo App"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # HTTP Ingress (Redirect to HTTPS by Caddy)
  ingress {
    description = "HTTP inbound for ACME challenge and redirect"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # SSH Ingress
  ingress {
    description = "Restricted SSH access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }

  # Outbound Egress
  egress {
    description = "Outbound traffic for package updates and ACME TLS validation"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "mini-sso-sg"
  }
}

# 3. AMI Discovery (Ubuntu 24.04 LTS)
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# 4. Optional SSH Key Pair
resource "aws_key_pair" "admin" {
  count      = var.ssh_public_key != "" ? 1 : 0
  key_name   = "mini-sso-key"
  public_key = var.ssh_public_key
}

# 5. EC2 Host Instance
resource "aws_instance" "host" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.web.id]
  key_name               = var.ssh_public_key != "" ? aws_key_pair.admin[0].key_name : null

  root_block_device {
    volume_size           = 20
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  user_data = <<-EOF
              #!/bin/bash
              set -euo pipefail

              # System updates & essential packages
              apt-get update -y
              apt-get upgrade -y
              apt-get install -y ca-certificates curl gnupg lsb-release fail2ban git

              # Install official Docker Engine & Compose plugin
              install -m 0755 -d /etc/apt/keyrings
              curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
              chmod a+r /etc/apt/keyrings/docker.asc
              echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
              apt-get update -y
              apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

              systemctl enable docker
              systemctl start docker
              systemctl enable fail2ban
              systemctl start fail2ban

              # Create app directory
              mkdir -p /opt/mini-sso
              chown -R ubuntu:ubuntu /opt/mini-sso
              EOF

  tags = {
    Name = "mini-sso-server"
  }
}

# 6. Elastic IP (Static Public IP)
resource "aws_eip" "ip" {
  instance = aws_instance.host.id
  domain   = "vpc"

  tags = {
    Name = "mini-sso-eip"
  }
}
