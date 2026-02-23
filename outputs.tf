output "pubsub_topic" {
  description = "Pub/Sub topic receiving PAM events"
  value       = google_pubsub_topic.pam_requests.id
}

output "log_sink_name" {
  description = "Name of the organization log sink"
  value       = google_logging_organization_sink.pam_sink.name
}

output "log_sink_writer_identity" {
  description = "Writer identity of the log sink"
  value       = google_logging_organization_sink.pam_sink.writer_identity
}

output "function_name" {
  description = "Name of the Cloud Function"
  value       = google_cloudfunctions2_function.pam_notifier.name
}

output "function_uri" {
  description = "URI of the Cloud Function"
  value       = google_cloudfunctions2_function.pam_notifier.url
}
