# GCP PAM Slackbot

A Terraform module that deploys a Slack notification bot for [Google Cloud Privileged Access Manager (PAM)](https://cloud.google.com/iam/docs/pam-overview) events. When users request, approve, deny, or withdraw privileged access grants, your team gets notified in Slack with rich formatted messages and direct links to the GCP Console.

## How It Works

```
GCP Audit Logs (PAM events)
        ↓
Organization Log Sink
        ↓
Cloud Pub/Sub Topic
        ↓
Cloud Function v2 (Python 3.12)
        ↓
Slack (channel + DMs)
```

The module creates an organization-level log sink that captures PAM audit log events and routes them to a Pub/Sub topic. A Cloud Function processes each event, enriches it with resource names and approver group information, and posts formatted messages to Slack.

## Notification Types

| Event | Channel Message | DM to Requester |
|-------|----------------|-----------------|
| New request (pending approval) | Yes — mentions approver groups | No |
| Auto-approved | Yes | No |
| Approved | Yes | Yes |
| Denied | Yes | Yes |
| Withdrawn | Yes | No |

## Prerequisites

- GCP Organization with [PAM enabled](https://cloud.google.com/iam/docs/pam-overview#enable-pam)
- A GCP project to host the infrastructure
- Terraform >= 1.0
- A Slack bot with the following OAuth scopes:
  - `chat:write`
  - `im:write` (required for DMs to requesters on approval/denial)
  - `users:lookupByEmail`
  - `usergroups:read`

## Usage

```hcl
module "pam_slackbot" {
  source = "github.com/cameronmills/gcp-pam-slackbot"

  org_id          = "123456789"
  project_id      = "my-central-project"
  slack_bot_token = var.slack_bot_token
  slack_channel   = "#pam-notifications"

  approver_slack_handle_map = {
    "engineering@example.com" = "engineering-team"
    "security@example.com" = "security-team"
  }
}
```

## Inputs

| Name | Description | Type | Required | Default |
|------|-------------|------|----------|---------|
| `org_id` | GCP Organization ID | `string` | Yes | — |
| `project_id` | GCP Project ID to deploy resources into | `string` | Yes | — |
| `slack_bot_token` | Slack bot OAuth token (`xoxb-...`) | `string` | Yes | — |
| `region` | Region for the Cloud Function | `string` | No | `us-central1` |
| `slack_channel` | Slack channel for notifications (e.g. `#pam-notifications`) | `string` | Yes | — |
| `approver_slack_handle_map` | Map of Google group emails to Slack user group handles | `map(string)` | No | `{}` |

## Outputs

| Name | Description |
|------|-------------|
| `pubsub_topic` | Pub/Sub topic ID |
| `log_sink_name` | Organization log sink name |
| `log_sink_writer_identity` | Writer service account for the log sink |
| `function_name` | Cloud Function name |
| `function_uri` | Cloud Function URL |

## Deployment

```bash
terraform init
terraform plan
terraform apply
```

The module provisions all required infrastructure, including:

- **Cloud Function v2** — processes PAM events (Python 3.12, 256 MB, up to 10 instances)
- **Organization Log Sink** — routes PAM audit logs org-wide to Pub/Sub
- **Cloud Pub/Sub Topic** — receives and buffers events
- **Secret Manager Secret** — stores the Slack bot token
- **Service Account + Custom IAM Role** — least-privilege access to Resource Manager and PAM APIs

### Required GCP APIs

The following APIs must be enabled in your project:

- `cloudfunctions.googleapis.com`
- `cloudbuild.googleapis.com`
- `pubsub.googleapis.com`
- `logging.googleapis.com`
- `secretmanager.googleapis.com`
- `run.googleapis.com`
- `privilegedaccessmanager.googleapis.com`

## Setting Up the Slack Bot

1. Go to [api.slack.com/apps](https://api.slack.com/apps) and create a new app
2. Under **OAuth & Permissions**, add the scopes: `chat:write`, `im:write`, `users:lookupByEmail`, `usergroups:read`
3. Install the app to your workspace and copy the **Bot User OAuth Token** (`xoxb-...`)
4. Invite the bot to your notification channel

## Approver Group Mapping

The `approver_slack_handle_map` variable maps Google group emails (configured as PAM approvers) to Slack user group handles. When a new access request is created, the bot mentions the relevant Slack group so approvers are notified.

```hcl
approver_slack_handle_map = {
  "engineering@example.com" = "engineering-team"  # @engineering-team in Slack
  "security@example.com" = "security-team"   # @security-team in Slack
}
```

## Contributing

This project uses [Conventional Commits](https://www.conventionalcommits.org/) and [release-please](https://github.com/googleapis/release-please) for automated changelog generation and versioning. Please follow the commit message format:

```
<type>: <description>

# Examples:
feat: add support for folder-scoped entitlements
fix: handle missing justification field gracefully
docs: update approver group mapping example
```

Common types: `feat`, `fix`, `docs`, `refactor`, `chore`. A `feat` commit bumps the minor version; a `fix` commit bumps the patch version. Breaking changes should include `BREAKING CHANGE:` in the commit body.

## Verifying the Deployment

```bash
# Check Cloud Function logs
gcloud functions logs read pam-slack-notifier --project=YOUR_PROJECT_ID --limit=50

# List Pub/Sub topics
gcloud pubsub topics list --project=YOUR_PROJECT_ID

# List organization log sinks
gcloud logging sinks list --organization=YOUR_ORG_ID
```
