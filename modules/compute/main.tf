terraform {
  required_version = ">= 1.10.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

# ==============================================================================
# Camada de Compute Econômica:
# - Application Load Balancer (ALB) com Health Check em /health/ready
# - Launch Template com IMDSv2 obrigatório e EBS criptografado
# - Auto Scaling Group de 1 instância EC2 pequena (t4g.micro / t3.micro)
# ==============================================================================

# Justificativa trivy:ignore:AVD-AWS-0053: O Application Load Balancer e intencionalmente internet-facing (internal = false) pois atua como ponto unico de entrada HTTP para os clientes externos; as instancias EC2 e o RDS nao aceitam trafego direto da internet.
# trivy:ignore:AVD-AWS-0053
resource "aws_lb" "app" {
  # checkov:skip=CKV_AWS_91:Access logs do ALB em S3 omitidos para evitar custo adicional de storage no ambiente de laboratorio.
  # checkov:skip=CKV_AWS_150:Deletion protection desabilitada para permitir execucao automatizada de tofu destroy ao final dos testes de ciclo de vida.
  # checkov:skip=CKV2_AWS_20:Redirecionamento HTTP->HTTPS exige dominio registrado e certificado ACM valido; no laboratorio sem dominio proprio o listener opera em HTTP (porta 80).
  # checkov:skip=CKV2_AWS_28:AWS WAFv2 omitido por decisao FinOps (WAF possui custo fixo mensal por Web ACL e Rule fora do escopo economico do laboratorio).
  name                       = "${var.project_name}-${var.environment}-alb"
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = [var.alb_security_group_id]
  subnets                    = var.public_subnet_ids
  drop_invalid_header_fields = true

  tags = {
    Name        = "${var.project_name}-${var.environment}-alb"
    Environment = var.environment
  }
}

resource "aws_lb_target_group" "app" {
  name        = "${var.project_name}-${var.environment}-tg"
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "instance"

  health_check {
    enabled             = true
    path                = "/health/ready"
    port                = "8000"
    protocol            = "HTTP"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 15
    matcher             = "200"
  }

  tags = {
    Name        = "${var.project_name}-${var.environment}-tg"
    Environment = var.environment
  }
}

# Justificativa trivy:ignore:AVD-AWS-0054: O listener do ALB usa protocolo HTTP na porta 80 no ambiente de emulacao/laboratorio por nao haver dominio DNS publico nem certificado ACM; em producao com Route53 + ACM habilita-se HTTPS 443 (TLS 1.3) com redirect 301 na porta 80.
# trivy:ignore:AVD-AWS-0054
resource "aws_lb_listener" "http" {
  # checkov:skip=CKV_AWS_2:Listener HTTP usado no ambiente de emulacao/laboratorio sem dominio publico registrado no ACM.
  # checkov:skip=CKV_AWS_103:Politica TLS 1.2+ aplica-se quando o protocolo HTTPS e certificado ACM estao configurados.
  load_balancer_arn = aws_lb.app.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

resource "aws_launch_template" "app" {
  # checkov:skip=CKV_AWS_88:Subnets publicas sem NAT Gateway exigem IP publico na EC2 para pull da imagem no GHCR; porta 8000 permanece bloqueada para a internet pelo app_sg
  name_prefix   = "${var.project_name}-${var.environment}-lt-"
  image_id      = var.ami_id
  instance_type = var.instance_type

  iam_instance_profile {
    name = var.instance_profile_name
  }

  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [var.app_security_group_id]
    delete_on_termination       = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 obrigatório
    http_put_response_hop_limit = 1
  }

  monitoring {
    enabled = true
  }

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size           = 20
      volume_type           = "gp3"
      encrypted             = true
      kms_key_id            = var.kms_key_arn
      delete_on_termination = true
    }
  }

  user_data = base64encode(templatefile("${path.module}/user_data.sh.tpl", {
    aws_region              = var.aws_region
    database_url_secret_arn = var.database_url_secret_arn
    app_image               = var.app_image
    environment             = var.environment
  }))

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name        = "${var.project_name}-${var.environment}-ec2"
      Environment = var.environment
    }
  }

  tags = {
    Name        = "${var.project_name}-${var.environment}-lt"
    Environment = var.environment
  }
}

resource "aws_autoscaling_group" "app" {
  name                      = "${var.project_name}-${var.environment}-asg"
  min_size                  = var.min_size
  max_size                  = var.max_size
  desired_capacity          = var.desired_capacity
  vpc_zone_identifier       = var.public_subnet_ids
  target_group_arns         = [aws_lb_target_group.app.arn]
  health_check_type         = "ELB"
  health_check_grace_period = 120

  launch_template {
    id      = aws_launch_template.app.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "${var.project_name}-${var.environment}-asg-instance"
    propagate_at_launch = true
  }

  tag {
    key                 = "Environment"
    value               = var.environment
    propagate_at_launch = true
  }
}
