resource "google_project_service" "default" {
  for_each = toset([
    "cloudfunctions.googleapis.com",
    "cloudbuild.googleapis.com",
    "pubsub.googleapis.com",
    "logging.googleapis.com",
    "secretmanager.googleapis.com",
    "run.googleapis.com",
    "privilegedaccessmanager.googleapis.com",
  ])

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}
