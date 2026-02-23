variable "org_id" {
  description = "GCP Organization ID"
  type        = string
}

variable "project_id" {
  description = "Central project ID where resources will be deployed"
  type        = string
}

variable "region" {
  description = "Region for Cloud Function deployment"
  type        = string
  default     = "us-central1"
}

variable "slack_bot_token" {
  description = "Slack bot OAuth token (xoxb-...)"
  type        = string
  sensitive   = true
}

variable "slack_channel" {
  description = "Slack channel to post notifications"
  type        = string
  default     = ""
}

variable "approver_slack_handle_map" {
  description = "Map of Google group email to Slack user group handle"
  type        = map(string)
  default     = {}
}
