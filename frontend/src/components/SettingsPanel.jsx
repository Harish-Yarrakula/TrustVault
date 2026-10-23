import { useEffect, useState } from "react";
import { api } from "../api";
import { evaluateAccessRules } from "../utils/accessRules";

export default function SettingsPanel({ user }) {
  const [guests, setGuests] = useState([]);
  const [shares, setShares] = useState([]);
  const [documents, setDocuments] = useState([]);
  const [selectedDocument, setSelectedDocument] = useState("");
  const [suggestions, setSuggestions] = useState([]);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  useEffect(() => {
    Promise.all([api.guests(), api.shares(), api.documents()])
      .then(([guestData, shareData, documentData]) => {
        setGuests(guestData);
        setShares(shareData);
        setDocuments(documentData);
      })
      .catch((requestError) => setError(requestError.message));
  }, []);

  const requestSuggestions = async () => {
    if (!selectedDocument) return;
    try {
      setError("");
      setSuggestions(await api.accessSuggestions({ document_id: selectedDocument }));
    } catch (requestError) {
      setError(requestError.message);
    }
  };

  const decideSuggestion = async (suggestion, approve) => {
    try {
      const updated = await api.decideAccessSuggestion(suggestion.id, { approve });
      setSuggestions((current) => current.filter((item) => item.id !== updated.id));
      setMessage(approve ? "Access granted after human confirmation." : "Suggestion rejected.");
    } catch (requestError) {
      setError(requestError.message);
    }
  };

  return (
    <section className="mt-6 max-w-4xl space-y-6">
      <div className="rounded-xl border border-gray-200 bg-white p-6">
        <h2 className="text-xl font-semibold text-gray-900">Account settings</h2>
        <p className="mt-1 text-sm text-gray-500">
          Your TrustVault identity and tenant access scope.
        </p>
        <dl className="mt-5 grid gap-4 sm:grid-cols-2">
          <div><dt className="text-xs uppercase text-gray-500">Email</dt><dd className="mt-1 text-sm">{user.email}</dd></div>
          <div><dt className="text-xs uppercase text-gray-500">Role</dt><dd className="mt-1 text-sm">{user.role}</dd></div>
          <div><dt className="text-xs uppercase text-gray-500">Account type</dt><dd className="mt-1 text-sm">{user.account_type}</dd></div>
          <div><dt className="text-xs uppercase text-gray-500">Company ID</dt><dd className="mt-1 break-all text-sm">{user.company_id}</dd></div>
        </dl>
      </div>

      {error && <p role="alert" className="rounded-lg bg-red-50 p-3 text-sm text-red-700">{error}</p>}
      {message && <p role="status" className="rounded-lg bg-green-50 p-3 text-sm text-green-700">{message}</p>}

      <div className="rounded-xl border border-gray-200 bg-white p-6">
        <h2 className="text-xl font-semibold text-gray-900">External guests</h2>
        <p className="mt-1 text-sm text-gray-500">Review external identities attached to this tenant.</p>
        <div className="mt-4 divide-y divide-gray-100">
          {guests.map((guest) => (
            <div key={guest.id} className="flex items-center justify-between py-3 text-sm">
              <span>{guest.email}</span>
              <span className="text-gray-500">{guest.status}</span>
            </div>
          ))}
          {!guests.length && <p className="py-3 text-sm text-gray-500">No external guests.</p>}
        </div>
      </div>

      <div className="rounded-xl border border-gray-200 bg-white p-6">
        <h2 className="text-xl font-semibold text-gray-900">Share links</h2>
        <p className="mt-1 text-sm text-gray-500">Review active and historical external delivery links.</p>
        <div className="mt-4 divide-y divide-gray-100">
          {shares.map((share) => (
            <div key={share.id} className="flex flex-wrap items-center justify-between gap-3 py-3 text-sm">
              <span>{share.recipient_email}</span>
              <span className="text-gray-500">{share.status} · {share.download_count}/{share.max_downloads}</span>
            </div>
          ))}
          {!shares.length && <p className="py-3 text-sm text-gray-500">No share links.</p>}
        </div>
      </div>

      <div className="rounded-xl border border-amber-200 bg-amber-50 p-6">
        <h2 className="text-xl font-semibold text-gray-900">AI access advisor</h2>
        <p className="mt-1 text-sm text-gray-700">
          AI may suggest least-privilege access, but it can never grant access automatically.
          An owner or administrator must confirm each suggestion, and both actions are audited.
        </p>
        <div className="mt-4 flex flex-wrap gap-3">
          <select value={selectedDocument} onChange={(event) => setSelectedDocument(event.target.value)} className="rounded border border-gray-300 bg-white px-3 py-2 text-sm">
            <option value="">Choose a document</option>
            {documents.map((document) => <option key={document.id} value={document.id}>{document.name}</option>)}
          </select>
          <button type="button" onClick={requestSuggestions} disabled={!selectedDocument} className="rounded bg-[#171440] px-3 py-2 text-sm text-white disabled:opacity-50">
            Suggest access
          </button>
        </div>
        {selectedDocument && (
          <div className="mt-4 rounded-lg border border-orange-200 bg-orange-50 p-3 text-sm text-gray-800">
            <h3 className="font-semibold">Rule-based safety checks</h3>
            <ul className="mt-2 space-y-2">
              {evaluateAccessRules(documents.find((document) => document.id === selectedDocument), user).map((finding) => (
                <li key={finding.id}><strong>{finding.severity.toUpperCase()}: {finding.title}.</strong> {finding.detail}</li>
              ))}
            </ul>
          </div>
        )}
        <div className="mt-4 space-y-3">
          {suggestions.map((suggestion) => (
            <div key={suggestion.id} className="rounded border border-amber-200 bg-white p-3 text-sm">
              <p><strong>{suggestion.suggested_email}</strong> · {suggestion.permission_level}</p>
              <p className="mt-1 text-gray-600">{suggestion.rationale}</p>
              <div className="mt-3 flex gap-2">
                <button type="button" onClick={() => decideSuggestion(suggestion, true)} className="rounded bg-green-700 px-3 py-1 text-white">Confirm</button>
                <button type="button" onClick={() => decideSuggestion(suggestion, false)} className="rounded border border-gray-300 px-3 py-1">Reject</button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
