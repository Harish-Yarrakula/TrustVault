import { useEffect, useState } from "react";
import { api } from "../api";
import { auditActionLabel, auditDetails } from "../utils/auditPresentation";

const AdminDashboard = () => {
  const [metrics, setMetrics] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([api.adminAnalytics(), api.audit()])
      .then(([analytics, events]) => {
        setMetrics({
          documents: analytics.documents,
          members: analytics.members,
          activeMembers: analytics.active_members,
          events: analytics.audit_events,
          alerts: analytics.alerts,
          eventBreakdown: analytics.event_breakdown,
          recentAlerts: events.filter((event) => ["USER_LOGIN_FAILED", "EMAIL_FAILED", "ACCESS_DENIED"].includes(event.action)).slice(0, 6),
        });
      })
      .catch((requestError) => setError(requestError.message));
  }, []);

  if (error) return <p role="alert" className="mt-6 text-sm text-red-600">{error}</p>;
  if (!metrics) return <p className="mt-6 text-sm text-gray-500">Loading analytics...</p>;

  return (
    <div className="mt-6 space-y-6">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {[
          ["Documents", metrics.documents],
          ["Company members", metrics.members],
          ["Active members", metrics.activeMembers],
          ["Audit events", metrics.events],
        ].map(([label, value]) => (
          <div key={label} className="rounded-xl border border-gray-200 bg-white p-5">
            <p className="text-sm text-gray-500">{label}</p>
            <p className="mt-2 text-3xl font-bold text-[#171440]">{value}</p>
          </div>
        ))}
      </div>
      <div className={`rounded-xl border p-5 ${metrics.alerts ? "border-red-200 bg-red-50" : "border-green-200 bg-green-50"}`}>
        <h2 className="font-semibold text-gray-900">Important alerts</h2>
        <p className="mt-1 text-sm text-gray-700">
          {metrics.alerts ? `${metrics.alerts} failed login or email-delivery event(s) need review in Document Logs.` : "No failed login or email-delivery alerts detected."}
        </p>
      </div>
      <div className="grid gap-6 lg:grid-cols-2">
        <section className="rounded-xl border border-gray-200 bg-white p-5">
          <h2 className="font-semibold text-gray-900">Activity analytics</h2>
          <p className="mt-1 text-sm text-gray-500">Audit activity grouped by event type.</p>
          <div className="mt-5 space-y-3">
            {Object.entries(metrics.eventBreakdown).sort(([, a], [, b]) => b - a).slice(0, 8).map(([action, count]) => {
              const max = Math.max(...Object.values(metrics.eventBreakdown), 1);
              return <div key={action}><div className="mb-1 flex justify-between text-xs"><span className="truncate text-gray-600">{action}</span><strong>{count}</strong></div><div className="h-2 rounded-full bg-gray-100"><div className="h-2 rounded-full bg-[#171440]" style={{ width: `${(count / max) * 100}%` }} /></div></div>;
            })}
            {!Object.keys(metrics.eventBreakdown).length && <p className="text-sm text-gray-500">No activity recorded.</p>}
          </div>
        </section>
        <section className="rounded-xl border border-gray-200 bg-white p-5">
          <h2 className="font-semibold text-gray-900">Alert timeline</h2>
          <div className="mt-4 space-y-3">
            {metrics.recentAlerts.map((event) => <div key={event.id} className="rounded-lg border border-red-100 bg-red-50 p-3 text-sm"><p className="font-semibold text-red-800">{auditActionLabel(event.action)}</p><p className="mt-1 text-xs text-red-700">{auditDetails(event.details, event.action)}</p><p className="mt-1 text-xs text-gray-500">{new Date(event.occurred_at).toLocaleString()}</p></div>)}
            {!metrics.recentAlerts.length && <p className="text-sm text-green-700">No active alerts.</p>}
          </div>
        </section>
      </div>
    </div>
  );
};

export default AdminDashboard;
