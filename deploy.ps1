# Advanced ML Threat Hunting Platform - Deployment Script

param(
    [Parameter(Mandatory=$false)]
    [switch]$AutoApprove = $false
)

Write-Host "Advanced ML Threat Hunting Platform" -ForegroundColor Cyan
Write-Host "Enterprise Security Solution" -ForegroundColor Green
Write-Host "Deploying advanced threat hunting platform with IPinfo integration..." -ForegroundColor Yellow

# Check prerequisites
Write-Host "Checking prerequisites..." -ForegroundColor Yellow

# Check Terraform
try {
    $terraformVersion = terraform version
    Write-Host "Terraform found: $($terraformVersion[0])" -ForegroundColor Green
} catch {
    Write-Host "Terraform not found. Please install Terraform >= 1.5.0" -ForegroundColor Red
    exit 1
}

# Check AWS CLI
try {
    $awsVersion = aws --version
    Write-Host "AWS CLI found: $awsVersion" -ForegroundColor Green
} catch {
    Write-Host "AWS CLI not found. Please install AWS CLI v2" -ForegroundColor Red
    exit 1
}

# Check AWS credentials
try {
    $awsIdentity = aws sts get-caller-identity --output json | ConvertFrom-Json
    Write-Host "AWS authenticated as: $($awsIdentity.Arn)" -ForegroundColor Green
} catch {
    Write-Host "AWS authentication failed. Please run 'aws configure'" -ForegroundColor Red
    exit 1
}

# Create Lambda deployment package with dependencies
Write-Host "Creating advanced Lambda deployment package..." -ForegroundColor Yellow

# Clean up previous package
if (Test-Path "threat_analyzer.zip") {
    Remove-Item "threat_analyzer.zip"
}
if (Test-Path "lambda_package") {
    Remove-Item -Recurse -Force "lambda_package"
}

# Create package directory
New-Item -ItemType Directory -Path "lambda_package" | Out-Null

# Copy Python file
Copy-Item "autonomous_threat_hunter.py" "lambda_package/"

# Create requirements.txt for Lambda layers (numpy is available in Lambda runtime)
@"
requests>=2.28.0
"@ | Out-File -FilePath "lambda_package/requirements.txt" -Encoding utf8

# Create the deployment package
Compress-Archive -Path "lambda_package/*" -DestinationPath "autonomous_threat_hunter.zip"

# Clean up
Remove-Item -Recurse -Force "lambda_package"

Write-Host "Advanced Lambda package created with ML capabilities" -ForegroundColor Green

# Initialize Terraform
Write-Host "Initializing Terraform..." -ForegroundColor Yellow
terraform init

if ($LASTEXITCODE -ne 0) {
    Write-Host "Terraform initialization failed" -ForegroundColor Red
    exit 1
}

# Validate configuration
Write-Host "Validating configuration..." -ForegroundColor Yellow
terraform validate

if ($LASTEXITCODE -ne 0) {
    Write-Host "Configuration validation failed" -ForegroundColor Red
    exit 1
}

# Plan deployment
Write-Host "Planning deployment..." -ForegroundColor Yellow
terraform plan -out=tfplan

if ($LASTEXITCODE -ne 0) {
    Write-Host "Planning failed" -ForegroundColor Red
    exit 1
}

# Apply deployment
Write-Host "Deploying threat hunting platform..." -ForegroundColor Yellow

if ($AutoApprove) {
    terraform apply -auto-approve tfplan
} else {
    Write-Host "Do you want to deploy the threat hunting platform? (yes/no): " -NoNewline -ForegroundColor Cyan
    $confirmation = Read-Host
    
    if ($confirmation -eq "yes") {
        terraform apply tfplan
    } else {
        Write-Host "Deployment cancelled." -ForegroundColor Yellow
        exit 0
    }
}

if ($LASTEXITCODE -ne 0) {
    Write-Host "Deployment failed" -ForegroundColor Red
    exit 1
}

# Get outputs
Write-Host "Retrieving deployment information..." -ForegroundColor Yellow
$outputs = terraform output -json | ConvertFrom-Json

Write-Host ""
Write-Host "DEPLOYMENT SUCCESSFUL!" -ForegroundColor Green
Write-Host ""
Write-Host "API Endpoint: $($outputs.api_endpoint.value)" -ForegroundColor White
Write-Host "ML Endpoint: $($outputs.sagemaker_endpoint.value)" -ForegroundColor White
Write-Host "Dashboard: $($outputs.dashboard_url.value)" -ForegroundColor White
Write-Host "Data Bucket: $($outputs.threat_bucket.value)" -ForegroundColor White
Write-Host ""
Write-Host "NEXT STEPS:" -ForegroundColor Cyan
Write-Host "1. Test the API with your threat hunting queries" -ForegroundColor White
Write-Host "2. Access CloudWatch Dashboard for monitoring" -ForegroundColor White
Write-Host "3. Configure additional threat intelligence feeds" -ForegroundColor White
Write-Host "4. Set up monitoring and alerting" -ForegroundColor White
Write-Host ""
Write-Host "Advanced ML Threat Hunting Platform is ready!" -ForegroundColor Green

# Clean up
Remove-Item tfplan -ErrorAction SilentlyContinue