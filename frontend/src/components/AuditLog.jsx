import { useEffect, useState } from "react";
import { api } from "../api";
import { auditActionLabel, auditDetails, auditIpLabel } from "../utils/auditPresentation";

const AuditLog = () => {
  const [events, setEvents] = useState([]);
  const [error, setError] = useState("");
  const [offset, setOffset] = useState(0);
  const [hasMore, setHasMore] = useState(true);

  useEffect(() => {
    api.audit({ limit: 50, offset: 0 }).then((rows) => {
      setEvents(rows);
      setHasMore(rows.length === 50);
    }).catch((requestError) => setError(requestError.message));
  }, []);

  const loadMore = async () => {
    const nextOffset = offset + 50;
    try {
      const rows = await api.audit({ limit: 50, offset: nextOffset });
      setEvents((current) => [...current, ...rows]);
      setOffset(nextOffset);
      setHasMore(rows.length === 50);
    } catch (requestError) {
      setError(requestError.message);
    }
  };

  return (
    <div className="mt-6 rounded-xl border border-gray-200 bg-white p-5">
      <h2 className="text-xl font-semibold text-gray-900">Activity and audit log</h2>
      <p className="mb-5 text-sm text-gray-500">Security and workspace activity in plain language.</p>
      {error && <p role="alert" className="mb-4 text-sm text-red-600">{error}</p>}
      <div className="overflow-x-auto">
        <table className="w-full min-w-[650px] text-left text-sm">
          <thead className="border-b border-gray-200 text-xs uppercase text-gray-500">
            <tr><th className="px-3 py-3">Event</th><th className="px-3 py-3">Actor</th><th className="px-3 py-3">Document</th><th className="px-3 py-3">IP address</th><th className="px-3 py-3">Details</th><th className="px-3 py-3">Time</th></tr>
          </thead>
          <tbody>
            {events.map((event) => (
              <tr key={event.id} className="border-b border-gray-100">
                <td className="px-3 py-4 font-medium text-gray-900">{auditActionLabel(event.action)}</td>
                <td className="px-3 py-4 text-gray-600">
                  {event.actor_name || event.actor_email
                    ? `${event.actor_name || "User"} · ${event.actor_email || ""}`
                    : "System"}
                </td>
                <td className="px-3 py-4 text-gray-600">{event.document_name || (event.document_id ? "Document activity" : "Workspace")}</td>
                <td className="px-3 py-4 text-gray-600">{auditIpLabel(event.ip_address)}</td>
                <td className="max-w-sm px-3 py-4 text-gray-600">{auditDetails(event.details, event.action)}</td>
                <td className="px-3 py-4 text-gray-600">{new Date(event.occurred_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {hasMore && <button type="button" onClick={loadMore} className="mt-4 rounded-lg border border-gray-300 px-3 py-2 text-sm font-semibold">Load more activity</button>}
      {!error && events.length === 0 && <p className="py-8 text-center text-sm text-gray-500">No audit events yet.</p>}
    </div>
  );
};

export default AuditLog;
