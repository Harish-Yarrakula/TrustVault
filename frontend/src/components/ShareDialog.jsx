import { useState } from "react";
import { api } from "../api";

const ShareDialog = ({ document, onClose }) => {
  const [recipientEmail, setRecipientEmail] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [link, setLink] = useState("");
  const [requireOtp, setRequireOtp] = useState(false);
  const [passcode, setPasscode] = useState("");

  const createShare = async (event) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const result = await api.createShare(document.id, {
        recipient_email: recipientEmail,
        require_otp: requireOtp,
        ...(passcode ? { passcode } : {}),
        expires_at: expiresAt ? new Date(expiresAt).toISOString() : new Date(Date.now() + 7 * 86400000).toISOString(),
      });
      setLink(new URL(result.url, window.location.origin).toString());
      if (recipientEmail) {
        setMessage(
          requireOtp
            ? `Share link and verification code sent to ${recipientEmail}.`
            : `Share link sent to ${recipientEmail}.`,
        );
      } else {
        setMessage("Share link created. Copy it below.");
      }
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  };

  const copyLink = async () => {
    await navigator.clipboard.writeText(link);
    setMessage("Link copied.");
  };

  return (
    <div className="fixed inset-0 z-30 flex items-center justify-center bg-black/40 p-4" role="dialog" aria-modal="true" aria-label="Share document">
      <form onSubmit={createShare} className="w-full max-w-lg rounded-2xl bg-white p-6 shadow-xl">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 className="text-xl font-semibold">Share {document.name}</h2>
            <p className="mt-1 text-sm text-gray-500">Send the secure link by email or copy it.</p>
          </div>
          <button type="button" onClick={onClose} className="text-gray-500" aria-label="Close share dialog">✕</button>
        </div>
        <label className="mt-5 block text-sm font-medium text-gray-700">
          Recipient email (optional)
          <input type="email" required={requireOtp} value={recipientEmail} onChange={(event) => setRecipientEmail(event.target.value)} placeholder="client@example.com" className="mt-2 w-full rounded-lg border border-gray-300 px-3 py-2" />
        </label>
        <label className="mt-4 block text-sm font-medium text-gray-700">
          Link expires
          <input type="datetime-local" required value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} className="mt-2 w-full rounded-lg border border-gray-300 px-3 py-2" />
        </label>
        <label className="mt-4 flex items-center gap-2 text-sm text-gray-700">
          <input type="checkbox" checked={requireOtp} onChange={(event) => setRequireOtp(event.target.checked)} />
          Require email OTP before download
        </label>
        {requireOtp && (
          <p className="mt-1 text-xs text-gray-500">
            Enter a recipient email; TrustVault sends the link and code in separate emails.
          </p>
        )}
        <label className="mt-4 block text-sm font-medium text-gray-700">
          Passcode (optional)
          <input type="password" minLength={6} value={passcode} onChange={(event) => setPasscode(event.target.value)} className="mt-2 w-full rounded-lg border border-gray-300 px-3 py-2" />
        </label>
        {error && <p role="alert" className="mt-3 text-sm text-red-600">{error}</p>}
        {message && <p role="status" className="mt-3 text-sm text-green-700">{message}</p>}
        {link && (
          <div className="mt-4 flex gap-2">
            <input readOnly value={link} className="min-w-0 flex-1 rounded-lg border border-gray-300 px-3 py-2 text-sm" aria-label="Share link" />
            <button type="button" onClick={copyLink} className="rounded-lg border border-gray-300 px-3 py-2 text-sm">Copy</button>
          </div>
        )}
        <div className="mt-6 flex justify-end gap-3">
          <button type="button" onClick={onClose} className="rounded-lg border border-gray-300 px-4 py-2 text-sm">Close</button>
          <button disabled={busy} type="submit" className="rounded-lg bg-[#171440] px-4 py-2 text-sm font-semibold text-white disabled:opacity-60">
            {busy ? "Creating..." : recipientEmail ? "Send by email" : "Create link"}
          </button>
        </div>
      </form>
    </div>
  );
};

export default ShareDialog;
