const actionLabels = {
  USER_LOGIN_SUCCESS: "Successful sign-in",
  USER_LOGIN_FAILED: "Failed sign-in",
  ACCESS_DENIED: "Access denied",
  EMAIL_FAILED: "Email delivery failed",
  DOCUMENT_CREATED: "Document uploaded",
  DOCUMENT_DOWNLOAD: "Document opened",
  DOCUMENT_DELETED: "Document deleted",
  DOCUMENT_UPDATED: "Document updated",
  PERMISSION_GRANTED: "Document assigned",
  PERMISSION_REVOKED: "Document access removed",
  AI_ACCESS_CONFIRMED: "Document assigned",
  GUEST_INVITED: "Guest invited",
  SHARE_LINK_CREATED: "Share link created",
  SHARE_LINK_REVOKED: "Share link revoked",
  EMAIL_SENT: "Email sent",
};

export function auditActionLabel(action) {
  return actionLabels[action] || "Workspace activity";
}

export function auditDetails(details, action) {
  if (!details || /method=\w+\s+path=\/api\/\S+\s+status=\d+/i.test(details)) {
    return actionLabels[action] || "Workspace activity recorded.";
  }
  try {
    const structured = JSON.parse(details);
    if (structured.type === "access_denied") {
      return "A protected workspace action was denied.";
    }
  } catch {
    // Older audit records used plain text details.
  }
  return details
    .replace(/message_id=\S+/gi, "notification sent")
    .replace(/recipient=[^\s]+/gi, "recipient recorded");
}

export function auditIpLabel(value) {
  if (!value) return "Unavailable";
  return ["127.0.0.1", "::1", "localhost"].includes(value)
    ? "Local development request"
    : value;
}
