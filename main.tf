resource "google_pubsub_topic" "pam_requests" {
  project = var.project_id
  name    = "pam-grant-requests"

  depends_on = [google_project_service.default]
}


resource "google_logging_organization_sink" "pam_sink" {
  name             = "pam-grant-request-sink"
  org_id           = var.org_id
  destination      = "pubsub.googleapis.com/${google_pubsub_topic.pam_requests.id}"
  include_children = true

  filter = <<-EOT
    protoPayload.serviceName="privilegedaccessmanager.googleapis.com" AND
    (
      protoPayload.methodName="google.cloud.privilegedaccessmanager.v1alpha.PrivilegedAccessManager.CreateGrant" OR
      protoPayload.methodName="google.cloud.privilegedaccessmanager.v1alpha.PrivilegedAccessManager.ApproveGrant" OR
      protoPayload.methodName="google.cloud.privilegedaccessmanager.v1alpha.PrivilegedAccessManager.DenyGrant" OR
      protoPayload.methodName="google.cloud.privilegedaccessmanager.v1alpha.PrivilegedAccessManager.WithdrawGrant"
    )
  EOT
}

# Grant the sink's service account permission to publish to the topic
resource "google_pubsub_topic_iam_member" "sink_publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.pam_requests.name
  role    = "roles/pubsub.publisher"
  member  = google_logging_organization_sink.pam_sink.writer_identity
}


resource "google_secret_manager_secret" "slack_bot_token" {
  project   = var.project_id
  secret_id = "pam-slack-bot-token"

  replication {
    auto {}
  }

  depends_on = [google_project_service.default]
}

resource "google_secret_manager_secret_version" "slack_bot_token" {
  secret      = google_secret_manager_secret.slack_bot_token.id
  secret_data = var.slack_bot_token
}


resource "google_service_account" "function_sa" {
  project      = var.project_id
  account_id   = "pam-slack-notifier"
  display_name = "PAM Slack Notifier Function"
}

# Allow the function to resolve resource display names
resource "google_organization_iam_custom_role" "resource_name_viewer" {
  org_id      = var.org_id
  role_id     = "pamNotifierResourceNameViewer"
  title       = "PAM Notifier Resource Name Viewer"
  description = "Allows resolving display names for organizations, folders, and projects, and fetching PAM entitlement details"
  permissions = [
    "resourcemanager.organizations.get",
    "resourcemanager.folders.get",
    "resourcemanager.projects.get",
    "privilegedaccessmanager.entitlements.get",
  ]
}

resource "google_organization_iam_member" "function_resource_viewer" {
  org_id = var.org_id
  role   = google_organization_iam_custom_role.resource_name_viewer.id
  member = "serviceAccount:${google_service_account.function_sa.email}"
}

resource "google_secret_manager_secret_iam_member" "function_secret_access" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.slack_bot_token.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.function_sa.email}"
}


data "archive_file" "function_source" {
  type        = "zip"
  output_path = "${path.module}/function-source.zip"
  source_dir  = "./function"
}

resource "google_storage_bucket" "function_bucket" {
  project                     = var.project_id
  name                        = "${var.project_id}-pam-notifier-source"
  location                    = var.region
  uniform_bucket_level_access = true
  force_destroy               = true

  depends_on = [google_project_service.default]
}

resource "google_storage_bucket_object" "function_source" {
  name   = "function-source-${data.archive_file.function_source.output_md5}.zip"
  bucket = google_storage_bucket.function_bucket.name
  source = data.archive_file.function_source.output_path
}


resource "google_cloudfunctions2_function" "pam_notifier" {
  project  = var.project_id
  name     = "pam-slack-notifier"
  location = var.region

  build_config {
    runtime     = "python312"
    entry_point = "handle_pam_event"

    source {
      storage_source {
        bucket = google_storage_bucket.function_bucket.name
        object = google_storage_bucket_object.function_source.name
      }
    }
  }

  service_config {
    min_instance_count    = 0
    max_instance_count    = 10
    available_memory      = "256M"
    timeout_seconds       = 60
    service_account_email = google_service_account.function_sa.email

    environment_variables = {
      SLACK_CHANNEL              = var.slack_channel
      APPROVER_SLACK_HANDLE_MAP  = jsonencode(var.approver_slack_handle_map)
    }

    secret_environment_variables {
      key        = "SLACK_BOT_TOKEN"
      project_id = var.project_id
      secret     = google_secret_manager_secret.slack_bot_token.secret_id
      version    = "latest"
    }
  }

  event_trigger {
    trigger_region = var.region
    event_type     = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic   = google_pubsub_topic.pam_requests.id
    retry_policy   = "RETRY_POLICY_RETRY"
  }

  depends_on = [
    google_project_service.default,
    google_secret_manager_secret_version.slack_bot_token,
  ]
}
