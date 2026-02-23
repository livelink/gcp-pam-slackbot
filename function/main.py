import base64
import json
import os
from datetime import datetime
from urllib import request, error

import functions_framework

# Map method name suffixes to event types
METHOD_SUFFIX_MAP = {
    "CreateGrant": "create",
    "ApproveGrant": "approve",
    "DenyGrant": "deny",
    "WithdrawGrant": "withdraw",
}

# Grant states that indicate auto-approval (no manual approval needed)
AUTO_APPROVED_STATES = {"ACTIVATED", "SCHEDULED"}


@functions_framework.cloud_event
def handle_pam_event(cloud_event):
    """Cloud Function triggered by Pub/Sub for PAM grant events."""

    # Decode the Pub/Sub message
    pubsub_message = cloud_event.data.get("message", {})
    message_data = pubsub_message.get("data", "")

    if not message_data:
        print("No data in Pub/Sub message")
        return

    # Decode base64 and parse JSON
    decoded_data = base64.b64decode(message_data).decode("utf-8")
    log_entry = json.loads(decoded_data)

    # Extract relevant information from the audit log
    proto_payload = log_entry.get("protoPayload", {})
    method_name = proto_payload.get("methodName", "")
    request_data = proto_payload.get("request", {})
    response_data = proto_payload.get("response", {})
    authentication_info = proto_payload.get("authenticationInfo", {})

    # Skip the first part of long-running operations (no response data yet)
    operation = log_entry.get("operation", {})
    if operation.get("first") and not operation.get("last"):
        print("Skipping first operation entry, waiting for completion")
        return

    # Skip failed requests (e.g. duplicate grant errors)
    status = proto_payload.get("status", {})
    if status.get("code", 0) != 0:
        print(f"Skipping failed PAM request: {status.get('message', 'unknown error')}")
        return

    # Determine event type from method name
    event_type = "unknown"
    for suffix, etype in METHOD_SUFFIX_MAP.items():
        if method_name.endswith(suffix):
            event_type = etype
            break

    if event_type == "unknown":
        print(f"Unrecognised PAM method: {method_name}")
        return

    # Get the actor (who performed this action)
    actor = authentication_info.get("principalEmail", "Unknown")

    # Get grant state from response
    grant_state = response_data.get("state", "")

    # Extract roles from the response - try privilegedAccess first, fall back to requestedPrivilegedAccess
    roles = []
    for access_key in ("privilegedAccess", "requestedPrivilegedAccess"):
        access_data = response_data.get(access_key, {})
        # Can be a dict (privilegedAccess) or a list (requestedPrivilegedAccess)
        if isinstance(access_data, list):
            for entry in access_data:
                for rb in entry.get("gcpIamAccess", {}).get("roleBindings", []):
                    if rb.get("role"):
                        roles.append(rb["role"])
        elif isinstance(access_data, dict):
            for rb in access_data.get("gcpIamAccess", {}).get("roleBindings", []):
                if rb.get("role"):
                    roles.append(rb["role"])
        if roles:
            break
    print(f"Extracted {len(roles)} roles: {roles}")
    display_roles = roles[:5]
    if len(roles) > 5:
        role = "\n".join(f"`{r}`" for r in display_roles) + f"\n_+{len(roles) - 5} more_"
    elif display_roles:
        role = "\n".join(f"`{r}`" for r in display_roles)
    else:
        role = "Unknown"

    requester = response_data.get("requester", actor)
    requested_duration = response_data.get("requestedDuration", "Unknown")
    justification = response_data.get("justification", {}).get("unstructuredJustification", "")

    # For CreateGrant, grant details are nested under request.grant
    if event_type == "create":
        grant_data = request_data.get("grant", {})
        if not requested_duration or requested_duration == "Unknown":
            requested_duration = grant_data.get("requestedDuration", "Unknown")
        if not justification:
            justification = grant_data.get("justification", {}).get("unstructuredJustification", "")

    # Parse scope from parent path or resource name
    # CreateGrant uses request.parent, others use response.name
    if event_type == "create":
        resource_path = request_data.get("parent", "")
    else:
        # response.name: organizations/ORG/locations/LOC/entitlements/ENT/grants/GRANT_ID
        resource_path = response_data.get("name", "")

    path_parts = resource_path.split("/")
    scope_type = path_parts[0] if len(path_parts) > 1 else "unknown"
    scope_id = path_parts[1] if len(path_parts) > 1 else "Unknown"
    entitlement_id = path_parts[5] if len(path_parts) > 5 else "Unknown"

    # Resolve display name for the scope
    scope_display_name = resolve_resource_name(scope_type, scope_id)

    if scope_type == "organizations":
        scope = f"Organization: {scope_display_name}"
        scope_param = f"organizationId={scope_id}"
    elif scope_type == "folders":
        scope = f"Folder: {scope_display_name}"
        scope_param = f"folder={scope_id}"
    elif scope_type == "projects":
        scope = f"Project: {scope_display_name}"
        scope_param = f"project={scope_id}"
    else:
        scope = f"Unknown: {scope_id}"
        scope_param = ""

    pam_base = "https://console.cloud.google.com/iam-admin/pam"
    timestamp = log_entry.get("timestamp", datetime.utcnow().isoformat())

    # Build event-specific message
    if event_type == "create" and grant_state in AUTO_APPROVED_STATES:
        slack_message = build_auto_approved_message(
            requester=requester, scope=scope, entitlement_id=entitlement_id,
            role=role, justification=justification,
            requested_duration=requested_duration,
            pam_url=f"{pam_base}/grants/all?{scope_param}",
            timestamp=timestamp,
        )
    elif event_type == "create":
        # Resolve approver tags for pending approval requests
        approver_tags = []
        entitlement_path = "/".join(path_parts[:6]) if len(path_parts) >= 6 else ""
        if entitlement_path:
            principals = get_entitlement_approvers(entitlement_path)
            for principal in principals:
                if principal.startswith("group:"):
                    tag = resolve_slack_group(principal)
                    if tag:
                        approver_tags.append(tag)

        slack_message = build_request_message(
            requester=requester, scope=scope, entitlement_id=entitlement_id,
            role=role, justification=justification,
            requested_duration=requested_duration,
            pam_url=f"{pam_base}/grants/approvals?{scope_param}",
            timestamp=timestamp,
            approver_tags=approver_tags,
        )
    elif event_type == "approve":
        slack_message = build_approved_message(
            requester=requester, approver=actor, scope=scope,
            entitlement_id=entitlement_id, role=role,
            pam_url=f"{pam_base}/grants/all?{scope_param}",
            timestamp=timestamp,
        )
        # DM the requester to let them know
        dm_notification(
            email=requester,
            text=f"Your PAM access request for *{entitlement_id}* ({scope}) has been *approved* by {actor}.",
        )
    elif event_type == "deny":
        slack_message = build_denied_message(
            requester=requester, denier=actor, scope=scope,
            entitlement_id=entitlement_id, role=role,
            pam_url=f"{pam_base}/grants/all?{scope_param}",
            timestamp=timestamp,
        )
        # DM the requester to let them know
        dm_notification(
            email=requester,
            text=f"Your PAM access request for *{entitlement_id}* ({scope}) has been *denied* by {actor}.",
        )
    elif event_type == "withdraw":
        slack_message = build_withdrawn_message(
            requester=requester, scope=scope,
            entitlement_id=entitlement_id, role=role,
            pam_url=f"{pam_base}/grants/all?{scope_param}",
            timestamp=timestamp,
        )

    send_slack_notification(slack_message)
    print(f"Notification sent for PAM {event_type} from {actor}")


def get_access_token():
    """Get an access token from the GCE metadata server."""
    metadata_url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
    req = request.Request(metadata_url, headers={"Metadata-Flavor": "Google"})
    with request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))["access_token"]


def resolve_resource_name(scope_type, scope_id):
    """Resolve a GCP resource ID to its display name via Resource Manager API."""
    try:
        token = get_access_token()

        if scope_type == "organizations":
            url = f"https://cloudresourcemanager.googleapis.com/v3/organizations/{scope_id}"
        elif scope_type == "folders":
            url = f"https://cloudresourcemanager.googleapis.com/v3/folders/{scope_id}"
        elif scope_type == "projects":
            url = f"https://cloudresourcemanager.googleapis.com/v3/projects/{scope_id}"
        else:
            return scope_id

        req = request.Request(url, headers={"Authorization": f"Bearer {token}"})
        with request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("displayName", scope_id)
    except Exception as e:
        print(f"Failed to resolve resource name for {scope_type}/{scope_id}: {e}")
        return scope_id


def format_duration(requested_duration):
    """Parse duration from seconds format (e.g. '3600s') to human-readable."""
    if not requested_duration or requested_duration == "Unknown":
        return "Unknown"
    if requested_duration.endswith("s"):
        try:
            seconds = int(requested_duration[:-1])
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            if hours > 0 and minutes > 0:
                return f"{hours}h {minutes}m"
            elif hours > 0:
                return f"{hours} hour(s)"
            else:
                return f"{minutes} minute(s)"
        except ValueError:
            return requested_duration
    return requested_duration


def slack_message_wrapper(blocks):
    """Wrap blocks in a Slack message with optional channel override."""
    message = {"blocks": blocks}
    slack_channel = os.environ.get("SLACK_CHANNEL", "")
    if slack_channel:
        message["channel"] = slack_channel
    return message


def build_request_message(requester, scope, entitlement_id, role, justification, requested_duration, pam_url, timestamp, approver_tags=None):
    """Pending approval request."""
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": "🔐 New PAM Access Request", "emoji": True}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Requester:*\n{requester}"},
            {"type": "mrkdwn", "text": f"*Scope:*\n{scope}"},
        ]},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Entitlement:*\n{entitlement_id}"},
            {"type": "mrkdwn", "text": f"*Role:*\n{role}"},
        ]},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Duration:*\n{format_duration(requested_duration)}"},
            {"type": "mrkdwn", "text": f"*Justification:*\n>{justification or 'None provided'}"},
        ]},
    ]

    if approver_tags:
        blocks.append({"type": "section", "text": {
            "type": "mrkdwn",
            "text": f"*Approvers:* {' '.join(approver_tags)}",
        }})

    blocks.extend([
        {"type": "actions", "elements": [
            {"type": "button", "text": {"type": "plain_text", "text": "Review in GCP Console", "emoji": True}, "url": pam_url, "style": "primary"},
        ]},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": f"Requested at {timestamp}"}]},
    ])

    return slack_message_wrapper(blocks)


def build_auto_approved_message(requester, scope, entitlement_id, role, justification, requested_duration, pam_url, timestamp):
    """Auto-approved grant."""
    return slack_message_wrapper([
        {"type": "header", "text": {"type": "plain_text", "text": "✅ PAM Access Automatically Approved", "emoji": True}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Requester:*\n{requester}"},
            {"type": "mrkdwn", "text": f"*Scope:*\n{scope}"},
        ]},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Entitlement:*\n{entitlement_id}"},
            {"type": "mrkdwn", "text": f"*Role:*\n{role}"},
        ]},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Duration:*\n{format_duration(requested_duration)}"},
            {"type": "mrkdwn", "text": f"*Justification:*\n>{justification or 'None provided'}"},
        ]},
        {"type": "actions", "elements": [
            {"type": "button", "text": {"type": "plain_text", "text": "View in GCP Console", "emoji": True}, "url": pam_url},
        ]},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": f"Approved at {timestamp}"}]},
    ])


def build_approved_message(requester, approver, scope, entitlement_id, role, pam_url, timestamp):
    """Manually approved grant."""
    return slack_message_wrapper([
        {"type": "header", "text": {"type": "plain_text", "text": "✅ PAM Access Request Approved", "emoji": True}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Requester:*\n{requester}"},
            {"type": "mrkdwn", "text": f"*Approved by:*\n{approver}"},
        ]},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Entitlement:*\n{entitlement_id}"},
            {"type": "mrkdwn", "text": f"*Role:*\n{role}"},
        ]},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Scope:*\n{scope}"},
        ]},
        {"type": "actions", "elements": [
            {"type": "button", "text": {"type": "plain_text", "text": "View in GCP Console", "emoji": True}, "url": pam_url},
        ]},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": f"Approved at {timestamp}"}]},
    ])


def build_denied_message(requester, denier, scope, entitlement_id, role, pam_url, timestamp):
    """Denied grant."""
    return slack_message_wrapper([
        {"type": "header", "text": {"type": "plain_text", "text": "❌ PAM Access Request Denied", "emoji": True}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Requester:*\n{requester}"},
            {"type": "mrkdwn", "text": f"*Denied by:*\n{denier}"},
        ]},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Entitlement:*\n{entitlement_id}"},
            {"type": "mrkdwn", "text": f"*Role:*\n{role}"},
        ]},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Scope:*\n{scope}"},
        ]},
        {"type": "actions", "elements": [
            {"type": "button", "text": {"type": "plain_text", "text": "View in GCP Console", "emoji": True}, "url": pam_url},
        ]},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": f"Denied at {timestamp}"}]},
    ])


def build_withdrawn_message(requester, scope, entitlement_id, role, pam_url, timestamp):
    """Withdrawn grant."""
    return slack_message_wrapper([
        {"type": "header", "text": {"type": "plain_text", "text": "↩️ PAM Access Request Withdrawn", "emoji": True}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Requester:*\n{requester}"},
            {"type": "mrkdwn", "text": f"*Scope:*\n{scope}"},
        ]},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Entitlement:*\n{entitlement_id}"},
            {"type": "mrkdwn", "text": f"*Role:*\n{role}"},
        ]},
        {"type": "actions", "elements": [
            {"type": "button", "text": {"type": "plain_text", "text": "View in GCP Console", "emoji": True}, "url": pam_url},
        ]},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": f"Withdrawn at {timestamp}"}]},
    ])


def send_slack_notification(message):
    """Send a notification to Slack via bot token and chat.postMessage."""

    bot_token = os.environ.get("SLACK_BOT_TOKEN")
    if not bot_token:
        raise ValueError("SLACK_BOT_TOKEN environment variable not set")

    data = json.dumps(message).encode("utf-8")

    req = request.Request(
        "https://slack.com/api/chat.postMessage",
        data=data,
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": f"Bearer {bot_token}",
        },
        method="POST",
    )

    try:
        with request.urlopen(req, timeout=10) as response:
            body = json.loads(response.read().decode("utf-8"))
            if not body.get("ok"):
                print(f"Slack API error: {body.get('error', 'unknown')}")
    except error.HTTPError as e:
        print(f"HTTP error sending to Slack: {e.code} - {e.reason}")
        raise
    except error.URLError as e:
        print(f"URL error sending to Slack: {e.reason}")
        raise


def get_entitlement_approvers(entitlement_path):
    """Fetch approver principals from a PAM entitlement's approval workflow."""
    try:
        token = get_access_token()
        url = f"https://privilegedaccessmanager.googleapis.com/v1beta/{entitlement_path}"
        req = request.Request(url, headers={"Authorization": f"Bearer {token}"})
        with request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        principals = []
        steps = data.get("approvalWorkflow", {}).get("manualApprovals", {}).get("steps", [])
        for step in steps:
            for approver in step.get("approvers", []):
                principals.extend(approver.get("principals", []))
        return principals
    except Exception as e:
        print(f"Failed to fetch entitlement approvers for {entitlement_path}: {e}")
        return []


def resolve_slack_group(google_group_principal):
    """Resolve a Google group principal to a Slack subteam mention string.

    Args:
        google_group_principal: e.g. "group:syseng@livelinktechnology.net"

    Returns:
        Slack mention string like "<!subteam^S12345>" or None if unresolvable.
    """
    handle_map_raw = os.environ.get("APPROVER_SLACK_HANDLE_MAP", "{}")
    try:
        handle_map = json.loads(handle_map_raw)
    except json.JSONDecodeError:
        print(f"Failed to parse APPROVER_SLACK_HANDLE_MAP: {handle_map_raw}")
        return None

    # Strip "group:" prefix
    email = google_group_principal.removeprefix("group:")

    slack_handle = handle_map.get(email)
    if not slack_handle:
        return None

    # Resolve handle to subteam ID via usergroups.list
    subteam_id = resolve_slack_subteam_id(slack_handle)
    if subteam_id:
        return f"<!subteam^{subteam_id}>"
    # Fall back to @handle text if API lookup fails
    return f"@{slack_handle}"


def resolve_slack_subteam_id(handle):
    """Resolve a Slack user group handle to its subteam ID."""
    bot_token = os.environ.get("SLACK_BOT_TOKEN")
    if not bot_token:
        return None

    req = request.Request(
        "https://slack.com/api/usergroups.list",
        headers={"Authorization": f"Bearer {bot_token}"},
    )

    try:
        with request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if not data.get("ok"):
                print(f"Slack usergroups.list error: {data.get('error')}")
                return None
            for group in data.get("usergroups", []):
                if group.get("handle") == handle:
                    return group.get("id")
    except Exception as e:
        print(f"Failed to resolve Slack subteam for handle '{handle}': {e}")

    return None


def resolve_slack_user_id(email):
    """Resolve an email address to a Slack user ID via users.lookupByEmail."""
    bot_token = os.environ.get("SLACK_BOT_TOKEN")
    if not bot_token:
        return None

    url = f"https://slack.com/api/users.lookupByEmail?email={email}"
    req = request.Request(url, headers={"Authorization": f"Bearer {bot_token}"})

    try:
        with request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if not data.get("ok"):
                print(f"Slack users.lookupByEmail error for {email}: {data.get('error')}")
                return None
            return data.get("user", {}).get("id")
    except Exception as e:
        print(f"Failed to resolve Slack user for {email}: {e}")

    return None


def dm_notification(email, text):
    """Send a DM to a user by their email address."""
    user_id = resolve_slack_user_id(email)
    if not user_id:
        print(f"Could not resolve Slack user for {email}, skipping DM")
        return

    bot_token = os.environ.get("SLACK_BOT_TOKEN")
    message = json.dumps({"channel": user_id, "text": text}).encode("utf-8")

    req = request.Request(
        "https://slack.com/api/chat.postMessage",
        data=message,
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": f"Bearer {bot_token}",
        },
        method="POST",
    )

    try:
        with request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            if not body.get("ok"):
                print(f"Slack DM error: {body.get('error')}")
            else:
                print(f"DM sent to {email}")
    except Exception as e:
        print(f"Failed to send DM to {email}: {e}")
