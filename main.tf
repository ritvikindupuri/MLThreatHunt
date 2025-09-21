terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  required_version = ">= 1.5.0"
}

provider "aws" {
  region = var.aws_region
}

# =============================================================================
# ADVANCED ML THREAT HUNTING PLATFORM
# =============================================================================

# S3 Bucket for threat data and ML models
resource "aws_s3_bucket" "threat_hunting_data" {
  bucket = "threat-hunting-ml-${random_id.suffix.hex}"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "threat_hunting_data" {
  bucket = aws_s3_bucket.threat_hunting_data.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "random_id" "suffix" {
  byte_length = 8
}

# Note: SageMaker endpoint will be added later - using Lambda ML for now

# Lambda function for real-time threat analysis
resource "aws_lambda_function" "threat_analyzer" {
  filename         = "autonomous_threat_hunter.zip"
  function_name    = "autonomous-ai-threat-hunter"
  role            = aws_iam_role.lambda_role.arn
  handler         = "autonomous_threat_hunter.handler"
  runtime         = "python3.9"
  timeout         = 300
  memory_size     = 1024

  environment {
    variables = {
      VIRUSTOTAL_API_KEY = var.virustotal_api_key
      THREAT_BUCKET     = aws_s3_bucket.threat_hunting_data.bucket
      SNS_TOPIC_ARN     = aws_sns_topic.threat_alerts.arn
    }
  }
}

# API Gateway for threat hunting API
resource "aws_api_gateway_rest_api" "threat_hunting_api" {
  name        = "advanced-threat-hunting-api"
  description = "Advanced ML-powered threat hunting API"
}

resource "aws_api_gateway_resource" "analyze" {
  rest_api_id = aws_api_gateway_rest_api.threat_hunting_api.id
  parent_id   = aws_api_gateway_rest_api.threat_hunting_api.root_resource_id
  path_part   = "analyze"
}

resource "aws_api_gateway_method" "analyze_post" {
  rest_api_id   = aws_api_gateway_rest_api.threat_hunting_api.id
  resource_id   = aws_api_gateway_resource.analyze.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "analyze_lambda" {
  rest_api_id = aws_api_gateway_rest_api.threat_hunting_api.id
  resource_id = aws_api_gateway_resource.analyze.id
  http_method = aws_api_gateway_method.analyze_post.http_method

  integration_http_method = "POST"
  type                   = "AWS_PROXY"
  uri                    = aws_lambda_function.threat_analyzer.invoke_arn
}

resource "aws_api_gateway_deployment" "threat_api" {
  depends_on = [aws_api_gateway_integration.analyze_lambda, aws_api_gateway_method.analyze_post]
  rest_api_id = aws_api_gateway_rest_api.threat_hunting_api.id
  
  # Force redeployment when method changes
  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_resource.analyze.id,
      aws_api_gateway_method.analyze_post.id,
      aws_api_gateway_integration.analyze_lambda.id,
    ]))
  }
  
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_stage" "prod" {
  deployment_id = aws_api_gateway_deployment.threat_api.id
  rest_api_id   = aws_api_gateway_rest_api.threat_hunting_api.id
  stage_name    = "prod"
}

# DynamoDB for threat intelligence storage
resource "aws_dynamodb_table" "threat_intelligence" {
  name           = "threat-intelligence-db"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "ip_address"
  range_key      = "timestamp"

  attribute {
    name = "ip_address"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S"
  }

  attribute {
    name = "threat_score"
    type = "N"
  }

  global_secondary_index {
    name               = "ThreatScoreIndex"
    hash_key           = "threat_score"
    projection_type    = "ALL"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }
}

# SNS for threat alerts
resource "aws_sns_topic" "threat_alerts" {
  name = "advanced-threat-alerts"
}

resource "aws_sns_topic_subscription" "email_alerts" {
  count     = var.notification_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.threat_alerts.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

# CloudWatch Dashboard for monitoring
resource "aws_cloudwatch_dashboard" "threat_hunting" {
  dashboard_name = "AdvancedThreatHunting"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/Lambda", "Invocations", "FunctionName", aws_lambda_function.threat_analyzer.function_name],
            ["AWS/Lambda", "Duration", "FunctionName", aws_lambda_function.threat_analyzer.function_name],
            ["AWS/Lambda", "Errors", "FunctionName", aws_lambda_function.threat_analyzer.function_name]
          ]
          period = 300
          stat   = "Average"
          region = var.aws_region
          title  = "Threat Detection Performance"
        }
      }
    ]
  })
}

# IAM Roles
resource "aws_iam_role" "sagemaker_role" {
  name = "threat-hunting-sagemaker-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "sagemaker.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "sagemaker_execution" {
  role       = aws_iam_role.sagemaker_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
}

resource "aws_iam_role" "lambda_role" {
  name = "threat-hunting-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "threat-hunting-lambda-policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "sagemaker:InvokeEndpoint",
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:Query",
          "dynamodb:Scan",
          "s3:GetObject",
          "s3:PutObject",
          "sns:Publish"
        ]
        Resource = "*"
      }
    ]
  })
}

# Lambda permission for API Gateway
resource "aws_lambda_permission" "api_gateway" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.threat_analyzer.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.threat_hunting_api.execution_arn}/*/*"
}

# Outputs
output "api_endpoint" {
  description = "API Gateway endpoint for threat analysis"
  value       = "https://${aws_api_gateway_rest_api.threat_hunting_api.id}.execute-api.${var.aws_region}.amazonaws.com/${aws_api_gateway_stage.prod.stage_name}"
}

output "autonomous_ai_function" {
  description = "Autonomous AI Threat Hunter function"
  value       = aws_lambda_function.threat_analyzer.function_name
}

output "dashboard_url" {
  description = "CloudWatch dashboard URL"
  value       = "https://console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=AdvancedThreatHunting"
}

output "threat_bucket" {
  description = "S3 bucket for threat data"
  value       = aws_s3_bucket.threat_hunting_data.bucket
}