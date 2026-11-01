variable "aws_region" {
  type        = string
  description = "AWS region for deployment"
  default     = "ap-northeast-1" # Tokyo region (fits HENNGE HQ)
}

variable "environment" {
  type        = string
  description = "Deployment environment"
  default     = "production"
}

variable "instance_type" {
  type        = string
  description = "EC2 instance size"
  default     = "t3.small"
}

variable "ssh_public_key" {
  type        = string
  description = "SSH public key content for administrative access"
  default     = ""
}

variable "admin_cidr" {
  type        = string
  description = "CIDR block permitted to access SSH port 22"
  default     = "0.0.0.0/0"
}

variable "idp_domain" {
  type        = string
  description = "Domain name for the IdP login service"
  default     = "auth.example.com"
}

variable "demo_domain" {
  type        = string
  description = "Domain name for the demo client application"
  default     = "app.example.com"
}

variable "acme_email" {
  type        = string
  description = "Contact email for Let's Encrypt TLS notifications"
  default     = "admin@example.com"
}
