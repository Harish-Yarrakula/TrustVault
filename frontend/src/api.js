const configuredApiUrl = import.meta.env.VITE_API_URL;
const API_URL = configuredApiUrl || "http://localhost:8000";
if (import.meta.env.PROD && (!configuredApiUrl || !configuredApiUrl.startsWith("https://"))) {
  throw new Error("VITE_API_URL must be an HTTPS URL in production.");
}

let accessToken = null;
export function setAccessToken(token) {
  accessToken = token;
}

async function request(path, options = {}) {
  const headers = new Headers(options.headers);
  if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
  if (options.body && !(options.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(`${API_URL}${path}`, {
    ...options,
    headers,
    credentials: "include",
  });
  if (response.status === 204) return null;
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = Array.isArray(data.detail)
      ? data.detail.map((item) => item.msg).join(" ")
      : data.detail;
    if (response.status === 401) accessToken = null;
    throw new Error(detail || "The server request failed.");
  }
  return data;
}

async function sha256(file) {
  const buffer = await file.arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export const api = {
  me: () => request("/users/me"),
  logout: () => request("/api/auth/logout", { method: "POST" }),
  documents: () => request("/api/documents"),
  sharedDocuments: () => request("/api/documents/shared-with-me"),
  createDocument: (data) =>
    request("/api/documents", { method: "POST", body: JSON.stringify(data) }),
  deleteDocument: (id) => request(`/api/documents/${id}`, { method: "DELETE" }),
  uploadDocument: async (file, category = "Other") => {
    const content_sha256 = await sha256(file);
    let document;
    try {
      document = await api.createDocument({
        name: file.name,
        category,
        content_sha256,
        content_type: file.type || "application/octet-stream",
      });
    } catch (error) {
      if (error.message.toLowerCase().includes("duplicate")) {
        throw new Error("This document has already been uploaded.", { cause: error });
      }
      throw error;
    }
    const upload = await request(`/api/documents/${document.id}/upload-url`, { method: "POST" });
    const uploadResponse = await fetch(upload.url, {
      method: "PUT",
      headers: {
        "Content-Type": file.type || "application/octet-stream",
        "x-amz-meta-content-sha256": content_sha256,
      },
      body: file,
    });
    if (!uploadResponse.ok) throw new Error(`Storage upload failed (${uploadResponse.status}).`);
    await request(`/api/documents/${document.id}/complete-upload`, { method: "POST" });
    return document;
  },
  downloadUrl: (id) => request(`/api/documents/${id}/download-url`),
  downloadContent: async (id) => {
    const response = await fetch(`${API_URL}/api/documents/${id}/content`, {
      headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : {},
    });
    if (!response.ok) throw new Error("The document could not be opened.");
    const contentDisposition = response.headers.get("Content-Disposition") || "";
    const encodedName = contentDisposition.match(/filename\*=UTF-8''([^;]+)/i)?.[1];
    const plainName = contentDisposition.match(/filename="([^"]+)"/i)?.[1];
    const filename = encodedName
      ? decodeURIComponent(encodedName)
      : plainName || "document";
    return { blob: await response.blob(), filename };
  },
  createShare: (id, data) =>
    request(`/api/documents/${id}/shares`, { method: "POST", body: JSON.stringify(data) }),
  shareDownload: (token, passcode) =>
    request(`/api/shares/${token}/download-url`, {
      method: "POST",
      body: JSON.stringify({ passcode: passcode || null }),
    }),
  shareContent: async (token, passcode) => {
    const response = await fetch(`${API_URL}/api/shares/${token}/download`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ passcode: passcode || null }),
    });
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      throw new Error(data.detail || "The shared document could not be opened.");
    }
    const contentDisposition = response.headers.get("Content-Disposition") || "";
    const encodedName = contentDisposition.match(/filename\*=UTF-8''([^;]+)/i)?.[1];
    const plainName = contentDisposition.match(/filename="([^"]+)"/i)?.[1];
    const filename = encodedName
      ? decodeURIComponent(encodedName)
      : plainName || "document";
    return { blob: await response.blob(), filename };
  },
  verifyShareOtp: (token, otp) =>
    request(`/api/shares/${token}/verify-otp`, {
      method: "POST",
      body: JSON.stringify({ otp }),
    }),
  verifyAudit: () => request("/api/audit/verify"),
  permissions: (id) => request(`/api/documents/${id}/permissions`),
  grantPermission: (id, data) =>
    request(`/api/documents/${id}/permissions`, { method: "POST", body: JSON.stringify(data) }),
  revokePermission: (documentId, permissionId) =>
    request(`/api/documents/${documentId}/permissions/${permissionId}`, { method: "DELETE" }),
  audit: (params = {}) => {
    const query = new URLSearchParams(params).toString();
    return request(`/api/audit${query ? `?${query}` : ""}`);
  },
  notifications: () => request("/api/notifications"),
  markNotificationsRead: (notificationIds) =>
    request("/api/notifications/read", {
      method: "POST",
      body: JSON.stringify({ notification_ids: notificationIds }),
    }),
  adminAnalytics: () => request("/api/admin/analytics"),
  guests: () => request("/api/guests"),
  shares: () => request("/api/shares"),
  accessSuggestions: (data) =>
    request("/api/ai/access-suggestions", { method: "POST", body: JSON.stringify(data) }),
  decideAccessSuggestion: (id, data) =>
    request(`/api/ai/access-suggestions/${id}/decision`, { method: "POST", body: JSON.stringify(data) }),
  members: () => request("/api/company/members"),
  inviteGuest: (data) =>
    request("/api/guests/invite", { method: "POST", body: JSON.stringify(data) }),
  acceptGuest: (token, password) =>
    request("/api/guests/accept", { method: "POST", body: JSON.stringify({ token, password }) }),
  updateMemberRole: (memberId, role) =>
    request(`/api/company/members/${memberId}`, { method: "PATCH", body: JSON.stringify({ role }) }),
};
