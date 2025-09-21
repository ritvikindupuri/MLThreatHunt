# =============================================================================
# ADVANCED ML THREAT HUNTING PLATFORM - VARIABLES
# =============================================================================

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "virustotal_api_key" {
  description = "VirusTotal API key for comprehensive threat intelligence"
  type        = string
  sensitive   = true
}

variable "notification_email" {
  description = "Email address for threat alerts"
  type        = string
  default     = ""
}

variable "threat_detection_sensitivity" {
  description = "Threat detection sensitivity (low, medium, high, critical)"
  type        = string
  default     = "high"
  
  validation {
    condition     = contains(["low", "medium", "high", "critical"], var.threat_detection_sensitivity)
    error_message = "Sensitivity must be: low, medium, high, or critical."
  }
}

variable "enable_advanced_features" {
  description = "Enable advanced enterprise features"
  type        = bool
  default     = true
}