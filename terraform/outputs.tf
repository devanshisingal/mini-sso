output "public_ip" {
  description = "Static Elastic IP allocated to Mini SSO host"
  value       = aws_eip.ip.public_ip
}

output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.host.id
}

output "ssh_connection_command" {
  description = "Command to SSH into host"
  value       = "ssh ubuntu@${aws_eip.ip.public_ip}"
}

output "dns_setup_instructions" {
  description = "DNS records to create with domain registrar"
  value       = <<EOT
Please configure the following DNS A records at your registrar:
  ${var.idp_domain}  IN A  ${aws_eip.ip.public_ip}
  ${var.demo_domain} IN A  ${aws_eip.ip.public_ip}

Caddy will automatically provision and renew Let's Encrypt TLS certificates once DNS propagates!
EOT
}
