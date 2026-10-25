const API_URL = import.meta.env.PROD ? "" : (import.meta.env.VITE_API_URL || "http://localhost:8000");

let accessToken = null;
export function setAccessToken(token) {
  accessToken = token;
}

function isJsonResponse(response) {
  const contentType = response.headers.get("Content-Type")?.toLowerCase() || "";
  return contentType.includes("application/json") || contentType.includes("+json");
}

function isDocumentResponse(response) {
  const contentType = response.headers.get("Content-Type")?.split(";", 1)[0].trim().toLowerCase();
  return ["application/pdf", "image/png", "image/jpeg"].includes(contentType);
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
  const jsonResponse = isJsonResponse(response);
  let data = {};
  if (jsonResponse) {
    try {
      data = await response.json();
    } catch {
      throw new Error("The API returned invalid JSON.");
    }
  }
  if (!response.ok) {
    const detail = Array.isArray(data.detail)
      ? data.detail.map((item) => item.msg).join(" ")
      : data.detail;
    if (response.status === 401) accessToken = null;
    const error = new Error(
      detail || (jsonResponse
        ? "The server request failed."
        : "The API returned a non-JSON response. Check the API URL and proxy configuration."),
    );
    error.status = response.status;
    throw error;
  }
  if (!jsonResponse) {
    throw new Error("The API returned a non-JSON response. Check the API URL and proxy configuration.");
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

function downloadFilename(contentDisposition) {
  const encodedName = contentDisposition.match(/filename\*=UTF-8''([^;]+)/i)?.[1];
  const plainName = contentDisposition.match(/filename="([^"]+)"/i)?.[1];
  return encodedName ? decodeURIComponent(encodedName) : plainName || "document";
}

export function saveDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

export const api = {
  me: () => request("/users/me"),
  logout: () => request("/api/auth/logout", { method: "POST" }),
  setupMfa: () => request("/api/auth/mfa/setup", { method: "POST" }),
  confirmMfa: (code) =>
    request("/api/auth/mfa/confirm", { method: "POST", body: JSON.stringify({ code }) }),
  verifyMfaChallenge: (challengeToken, code) =>
    request("/api/auth/mfa/verify", {
      method: "POST",
      body: JSON.stringify({ challenge_token: challengeToken, code }),
    }),
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
        file_size: file.size,
      });
    } catch (error) {
      if (
        error.message.toLowerCase().includes("duplicate") ||
        error.message.toLowerCase().includes("identical contents")
      ) {
        throw new Error("A document with identical contents already exists in this company workspace.", { cause: error });
      }
      throw error;
    }
    try {
      const upload = await request(`/api/documents/${document.id}/upload-url`, { method: "POST" });
      const form = new FormData();
      Object.entries(upload.fields).forEach(([name, value]) => form.append(name, value));
      form.append("file", file);
      const uploadResponse = await fetch(upload.url, { method: "POST", body: form });
      if (!uploadResponse.ok) throw new Error(`Storage upload failed (${uploadResponse.status}).`);
      await request(`/api/documents/${document.id}/complete-upload`, { method: "POST" });
      return document;
    } catch (uploadError) {
      try {
        await api.deleteDocument(document.id);
      } catch (cleanupError) {
        throw new Error(
          `Upload failed: ${uploadError.message}. The incomplete upload could not be cleaned up, so retry may remain blocked.`,
          { cause: cleanupError },
        );
      }
      throw uploadError;
    }
  },
  downloadUrl: (id) => request(`/api/documents/${id}/download-url`),
  downloadContent: async (id) => {
    const response = await fetch(`${API_URL}/api/documents/${id}/content`, {
      headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : {},
      credentials: "include",
    });
    if (!response.ok) {
      const data = isJsonResponse(response) ? await response.json().catch(() => ({})) : {};
      const detail = Array.isArray(data.detail)
        ? data.detail.map((item) => item.msg).join(" ")
        : data.detail;
      if (response.status === 401) accessToken = null;
      throw new Error(detail || "The document could not be opened.");
    }
    if (!isDocumentResponse(response)) {
      throw new Error("The API did not return a supported document. Check the API URL and proxy configuration.");
    }
    const blob = await response.blob();
    const contentDisposition = response.headers.get("Content-Disposition") || "";
    return { blob, filename: downloadFilename(contentDisposition) };
  },
  createShare: (id, data) =>
    request(`/api/documents/${id}/shares`, { method: "POST", body: JSON.stringify(data) }),
  exchangeShareToken: (token) =>
    request("/api/shares/exchange", { method: "POST", body: JSON.stringify({ token }) }),
  shareContent: async (passcode) => {
    const response = await fetch(`${API_URL}/api/shares/current/download`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ passcode: passcode || null }),
    });
    if (!response.ok) {
      const data = isJsonResponse(response) ? await response.json().catch(() => ({})) : {};
      throw new Error(data.detail || "The shared document could not be opened.");
    }
    if (!isDocumentResponse(response)) {
      throw new Error("The API did not return a supported document. Check the API URL and proxy configuration.");
    }
    const blob = await response.blob();
    const contentDisposition = response.headers.get("Content-Disposition") || "";
    return { blob, filename: downloadFilename(contentDisposition) };
  },
  verifyShareOtp: (otp) =>
    request("/api/shares/current/verify-otp", {
      method: "POST",
      body: JSON.stringify({ otp }),
    }),
  resendShareOtp: () =>
    request("/api/shares/current/resend-otp", { method: "POST" }),
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
  inviteCompanyMember: (email) =>
    request("/api/company/invitations", { method: "POST", body: JSON.stringify({ email }) }),
  inviteGuest: (data) =>
    request("/api/guests/invite", { method: "POST", body: JSON.stringify(data) }),
  acceptGuest: (token, password) =>
    request("/api/guests/accept", { method: "POST", body: JSON.stringify({ token, password }) }),
  updateMemberRole: (memberId, role) =>
    request(`/api/company/members/${memberId}`, { method: "PATCH", body: JSON.stringify({ role }) }),
};
