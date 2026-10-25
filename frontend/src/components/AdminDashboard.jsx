import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { auditActionLabel, auditDetails } from "../utils/auditPresentation";

const signalActions = new Set(["USER_LOGIN_FAILED", "EMAIL_FAILED", "ACCESS_DENIED"]);
const updateActions = new Set([
  "DOCUMENT_CREATED",
  "DOCUMENT_UPDATED",
  "DOCUMENT_DELETED",
  "PERMISSION_GRANTED",
  "PERMISSION_REVOKED",
  "AI_ACCESS_CONFIRMED",
  "GUEST_INVITED",
]);
const chartColors = ["#38bdf8", "#a78bfa", "#fbbf24", "#34d399", "#fb7185", "#818cf8"];

function buildActivityByDay(events) {
  const today = new Date();
  const todayKey = today.toISOString().slice(0, 10);
  const counts = new Map();
  const days = Array.from({ length: 30 }, (_, index) => {
    const date = new Date(`${todayKey}T00:00:00.000Z`);
    date.setUTCDate(date.getUTCDate() - (29 - index));
    return date.toISOString().slice(0, 10);
  });
  const daysInRange = new Set(days);

  events.forEach((event) => {
    const timestamp = Date.parse(event.occurred_at);
    if (!Number.isFinite(timestamp)) return;
    const day = new Date(timestamp).toISOString().slice(0, 10);
    if (daysInRange.has(day)) counts.set(day, (counts.get(day) || 0) + 1);
  });

  return days.map((date) => ({ date, count: counts.get(date) || 0 }));
}

function buildEventBreakdown(events) {
  const cutoff = new Date();
  cutoff.setUTCDate(cutoff.getUTCDate() - 29);
  const breakdown = {};
  events.forEach((event) => {
    const timestamp = Date.parse(event.occurred_at);
    if (!Number.isFinite(timestamp) || timestamp < cutoff.getTime()) return;
    breakdown[event.action] = (breakdown[event.action] || 0) + 1;
  });
  return breakdown;
}

function buildDocumentCategories(documents) {
  return documents.reduce((categories, document) => {
    const category = document.category || "Uncategorized";
    categories[category] = (categories[category] || 0) + 1;
    return categories;
  }, {});
}

function MetricCard({ label, value, note, color }) {
  return (
    <article className="min-w-0 rounded-xl border border-white/10 bg-white/[0.04] p-4">
      <p className="text-xs font-medium text-slate-400">{label}</p>
      <div className="mt-3 flex items-end justify-between gap-3">
        <p className="text-2xl font-semibold tracking-tight text-white">{value ?? "—"}</p>
        <span className={`mb-1 size-2 rounded-full ${color}`} aria-hidden="true" />
      </div>
      <p className="mt-2 truncate text-xs text-slate-500">{note}</p>
    </article>
  );
}

function ActivityChart({ points }) {
  if (!Array.isArray(points)) {
    return <ChartMessage>Daily activity data is unavailable.</ChartMessage>;
  }
  if (!points.length || points.every((point) => !point.count)) {
    return <ChartMessage>No audit activity was recorded for this period.</ChartMessage>;
  }

  const maximum = Math.max(...points.map((point) => point.count), 1);
  const labelIndexes = [0, 7, 14, 21, points.length - 1].filter(
    (index, position, indexes) => points[index] && indexes.indexOf(index) === position,
  );
  const chartWidth = 720;
  const chartHeight = 205;
  const chartTop = 12;
  const chartBottom = 165;
  const barWidth = Math.max(2, Math.min(12, (chartWidth - 40) / points.length - 4));
  const gap = (chartWidth - 40 - barWidth * points.length) / Math.max(points.length - 1, 1);

  return (
    <div className="overflow-x-auto">
      <svg
        viewBox={`0 0 ${chartWidth} ${chartHeight}`}
        className="h-auto min-w-[540px] w-full"
        role="img"
        aria-label="Daily audit activity over the last 30 days"
      >
        {[0, 0.5, 1].map((fraction) => {
          const y = chartTop + (chartBottom - chartTop) * fraction;
          return (
            <g key={fraction}>
              <line x1="32" y1={y} x2={chartWidth} y2={y} stroke="#334155" strokeDasharray="4 6" />
              <text x="24" y={y + 4} textAnchor="end" fill="#94a3b8" fontSize="10">
                {Math.round(maximum * (1 - fraction))}
              </text>
            </g>
          );
        })}
        {points.map((point, index) => {
          const height = point.count ? Math.max(3, (point.count / maximum) * (chartBottom - chartTop)) : 0;
          return (
            <g key={point.date}>
              <rect
                x={36 + index * (barWidth + gap)}
                y={chartBottom - height}
                width={barWidth}
                height={height}
                rx="3"
                fill={point.count ? "#38bdf8" : "#334155"}
                opacity={point.count ? "0.9" : "0.45"}
              >
                <title>{point.date}: {point.count} audit events</title>
              </rect>
            </g>
          );
        })}
        {labelIndexes.map((index) => (
          <text
            key={points[index].date}
            x={36 + index * (barWidth + gap)}
            y="192"
            fill="#94a3b8"
            fontSize="10"
            textAnchor={index === 0 ? "start" : index === points.length - 1 ? "end" : "middle"}
          >
            {new Date(`${points[index].date}T00:00:00`).toLocaleDateString(undefined, { month: "short", day: "numeric" })}
          </text>
        ))}
      </svg>
    </div>
  );
}

function CategoryDonut({ categories }) {
  const entries = Object.entries(categories || {})
    .filter(([, count]) => Number.isFinite(count) && count > 0)
    .sort(([, left], [, right]) => right - left);
  const total = entries.reduce((sum, [, count]) => sum + count, 0);
  const radius = 42;
  const circumference = 2 * Math.PI * radius;
  const segments = entries.map(([category, count], index) => ({
    category,
    count,
    color: chartColors[index % chartColors.length],
    length: (count / total) * circumference,
    offset: entries
      .slice(0, index)
      .reduce((sum, [, previousCount]) => sum + (previousCount / total) * circumference, 0),
  }));

  return (
    <div className="grid items-center gap-5 sm:grid-cols-[150px_1fr]">
      <div className="relative mx-auto size-36">
        {total ? (
          <>
            <svg viewBox="0 0 110 110" className="size-full -rotate-90" role="img" aria-label={`Documents grouped into ${entries.length} categories`}>
              <circle cx="55" cy="55" r={radius} fill="none" stroke="#1e293b" strokeWidth="15" />
              {segments.map((segment) => (
                  <circle
                    key={segment.category}
                    cx="55"
                    cy="55"
                    r={radius}
                    fill="none"
                    stroke={segment.color}
                    strokeWidth="15"
                    strokeDasharray={`${segment.length} ${circumference - segment.length}`}
                    strokeDashoffset={-segment.offset}
                  >
                    <title>{segment.category}: {segment.count} documents</title>
                  </circle>
              ))}
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-2xl font-semibold text-white">{total}</span>
              <span className="text-[10px] text-slate-400">documents</span>
            </div>
          </>
        ) : (
          <div className="flex size-full items-center justify-center rounded-full border-[14px] border-slate-800 text-xs text-slate-500">
            {categories ? "No documents" : "Unavailable"}
          </div>
        )}
      </div>
      <div className="space-y-3">
        {entries.length ? entries.slice(0, 6).map(([category, count], index) => (
          <div key={category} className="flex items-center justify-between gap-3 text-xs">
            <span className="flex min-w-0 items-center gap-2 text-slate-300">
              <span className="size-2 shrink-0 rounded-full" style={{ backgroundColor: chartColors[index % chartColors.length] }} />
              <span className="truncate">{category}</span>
            </span>
            <span className="font-medium tabular-nums text-white">{count}</span>
          </div>
        )) : (
          <p className="text-xs leading-5 text-slate-500">
            {categories ? "Documents will appear here when they have been added." : "Category totals are not available from the analytics API."}
          </p>
        )}
      </div>
    </div>
  );
}

function EventBreakdown({ entries }) {
  const rows = Object.entries(entries || {})
    .filter(([, count]) => Number.isFinite(count) && count > 0)
    .sort(([, left], [, right]) => right - left)
    .slice(0, 6);
  const maximum = Math.max(...rows.map(([, count]) => count), 1);

  if (!rows.length) {
    return <ChartMessage>{entries ? "No audit events were recorded for this period." : "Event totals are unavailable."}</ChartMessage>;
  }

  return (
    <div className="space-y-4">
      {rows.map(([action, count], index) => (
        <div key={action}>
          <div className="mb-1.5 flex items-center justify-between gap-3 text-xs">
            <span className="truncate text-slate-300">{auditActionLabel(action)}</span>
            <span className="tabular-nums text-white">{count}</span>
          </div>
          <div className="h-1.5 overflow-hidden rounded-full bg-slate-800">
            <div
              className="h-full rounded-full"
              style={{ width: `${(count / maximum) * 100}%`, backgroundColor: chartColors[index % chartColors.length] }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

function ChartMessage({ children }) {
  return (
    <div className="flex min-h-40 items-center justify-center rounded-lg border border-dashed border-white/10 px-4 text-center text-xs text-slate-500">
      {children}
    </div>
  );
}

function DashboardPanel({ title, description, action, children, className = "" }) {
  return (
    <section className={`min-w-0 rounded-xl border border-white/10 bg-white/[0.04] p-4 sm:p-5 ${className}`}>
      <div className="mb-5 flex items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-white">{title}</h2>
          <p className="mt-1 text-xs text-slate-500">{description}</p>
        </div>
        {action && <span className="shrink-0 text-[10px] text-slate-500">{action}</span>}
      </div>
      {children}
    </section>
  );
}

const AdminDashboard = () => {
  const [metrics, setMetrics] = useState(null);
  const [events, setEvents] = useState([]);
  const [documents, setDocuments] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    Promise.all([api.adminAnalytics(), api.audit({ limit: 500 }), api.documents()])
      .then(([analytics, auditEvents, companyDocuments]) => {
        if (!active) return;
        setMetrics(analytics);
        setEvents(Array.isArray(auditEvents) ? auditEvents : []);
        setDocuments(Array.isArray(companyDocuments) ? companyDocuments : []);
      })
      .catch((requestError) => {
        if (active) setError(requestError.message);
      });
    return () => {
      active = false;
    };
  }, []);

  const recentAlerts = useMemo(() => {
    if (Array.isArray(metrics?.recent_alerts)) return metrics.recent_alerts;
    return events.filter((event) => signalActions.has(event.action)).slice(0, 5);
  }, [events, metrics]);
  const recentUpdates = useMemo(
    () => events.filter((event) => updateActions.has(event.action)).slice(0, 6),
    [events],
  );
  const fallbackActivity = useMemo(() => buildActivityByDay(events), [events]);
  const fallbackEventBreakdown = useMemo(() => buildEventBreakdown(events), [events]);
  const fallbackCategories = useMemo(() => buildDocumentCategories(documents), [documents]);

  if (error) return <p role="alert" className="mx-auto mt-6 max-w-6xl rounded-lg bg-red-50 p-4 text-sm text-red-700">{error}</p>;
  if (!metrics) return <p className="mx-auto mt-6 max-w-6xl text-sm text-gray-500">Loading workspace insights...</p>;

  const activeMemberRate = Number.isFinite(metrics.members) && metrics.members > 0 && Number.isFinite(metrics.active_members)
    ? `${Math.round((metrics.active_members / metrics.members) * 100)}%`
    : "—";
  const metricCards = [
    { label: "Documents", value: metrics.documents ?? documents.length, note: "Company document records", color: "bg-sky-400" },
    { label: "Members", value: metrics.members, note: `${metrics.active_members ?? "—"} active`, color: "bg-violet-400" },
    { label: "Active members", value: activeMemberRate, note: "Of all company members", color: "bg-emerald-400" },
    { label: "Audit events", value: metrics.audit_events ?? "—", note: `${metrics.events_30d ?? fallbackActivity.reduce((sum, point) => sum + point.count, 0)} in the last 30 days`, color: "bg-amber-400" },
  ];
  const activityPoints = Array.isArray(metrics.activity_by_day) &&
    (metrics.activity_by_day.some((point) => point.count > 0) || !events.length)
    ? metrics.activity_by_day
    : fallbackActivity;
  const documentCategories = Object.keys(metrics.documents_by_category || {}).length || !documents.length
    ? metrics.documents_by_category
    : fallbackCategories;
  const eventBreakdown = Object.keys(metrics.event_breakdown || {}).length || !events.length
    ? metrics.event_breakdown
    : fallbackEventBreakdown;
  const hasServerActivity = Array.isArray(metrics.activity_by_day) && metrics.activity_by_day.some((point) => point.count > 0);

  return (
    <div className="mx-auto mt-6 w-full max-w-7xl px-1">
      <div className="overflow-hidden rounded-2xl bg-[#0b1220] p-4 text-white shadow-xl sm:p-6 lg:p-7">
        <header className="mb-6 flex flex-wrap items-end justify-between gap-4">
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-sky-400">Company workspace</p>
            <h1 className="mt-2 text-2xl font-semibold tracking-tight text-white sm:text-3xl">Workspace overview</h1>
            <p className="mt-1 text-sm text-slate-400">Security, documents, and activity from your organization.</p>
          </div>
          <div className="flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.04] px-3 py-1.5 text-xs text-slate-300">
            <span className="size-2 rounded-full bg-emerald-400" />
            Organization data
          </div>
        </header>

        <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4" aria-label="Workspace metrics">
          {metricCards.map((card) => (
            <MetricCard key={card.label} {...card} />
          ))}
        </section>

        <div className="mt-4 grid gap-4 xl:grid-cols-[1.65fr_1fr]">
          <DashboardPanel
            title="Workspace activity"
            description={hasServerActivity ? "Daily audit events recorded over the last 30 days." : "Daily counts from the latest 500 audit records."}
            action={`${metrics.events_30d ?? fallbackActivity.reduce((sum, point) => sum + point.count, 0)} events · 30 days`}
          >
            <ActivityChart points={activityPoints} />
          </DashboardPanel>
          <DashboardPanel
            title="Documents by category"
            description="Current company documents grouped by category."
            action={`${Object.values(documentCategories || {}).reduce((sum, count) => sum + count, 0)} total`}
          >
            <CategoryDonut categories={documentCategories} />
          </DashboardPanel>
        </div>

        <div className="mt-4 grid gap-4 xl:grid-cols-2">
          <DashboardPanel
            title="Activity by event type"
            description="Audit events recorded during the last 30 days."
            action="Top event types"
          >
            <EventBreakdown entries={eventBreakdown} />
          </DashboardPanel>
          <DashboardPanel
            title="Latest security signals"
            description="Failed sign-ins, denied access, and email delivery issues."
            action={Number.isFinite(metrics.alerts_30d) ? `${metrics.alerts_30d} · 30 days` : "Recent events"}
          >
            {recentAlerts.length ? (
              <div className="space-y-3">
                {recentAlerts.slice(0, 5).map((event) => (
                  <article key={event.id} className="flex items-start justify-between gap-4 border-b border-white/[0.07] pb-3 last:border-0 last:pb-0">
                    <div className="min-w-0">
                      <p className="truncate text-xs font-medium text-slate-200">{auditActionLabel(event.action)}</p>
                      <p className="mt-1 line-clamp-2 text-xs text-slate-500">{auditDetails(event.details, event.action)}</p>
                      {(event.actor_name || event.actor_email) && (
                        <p className="mt-1 text-[10px] text-slate-500">{event.actor_name || event.actor_email}</p>
                      )}
                    </div>
                    <time className="shrink-0 text-[10px] text-slate-500" dateTime={event.occurred_at}>
                      {new Date(event.occurred_at).toLocaleDateString()}
                    </time>
                  </article>
                ))}
              </div>
            ) : (
              <ChartMessage>
                {metrics.alerts_30d === 0
                  ? "No security events were recorded in the last 30 days."
                  : "No recent security events were returned."}
              </ChartMessage>
            )}
          </DashboardPanel>
        </div>

        <DashboardPanel
          title="Recent workspace updates"
          description="Recent document changes and access assignments."
          action="Latest audit activity"
          className="mt-4"
        >
          {recentUpdates.length ? (
            <div className="grid gap-x-6 sm:grid-cols-2">
              {recentUpdates.map((event) => (
                <article key={event.id} className="flex min-w-0 items-start justify-between gap-3 border-b border-white/[0.07] py-3 first:pt-0 sm:nth-[n+3]:border-b-0">
                  <div className="min-w-0">
                    <p className="truncate text-xs font-medium text-slate-200">{auditActionLabel(event.action)}</p>
                    <p className="mt-1 truncate text-xs text-slate-500">
                      {event.document_name || auditDetails(event.details, event.action)}
                      {event.actor_name ? ` · ${event.actor_name}` : ""}
                    </p>
                  </div>
                  <time className="shrink-0 text-[10px] text-slate-500" dateTime={event.occurred_at}>
                    {new Date(event.occurred_at).toLocaleDateString()}
                  </time>
                </article>
              ))}
            </div>
          ) : (
            <ChartMessage>No document updates or access assignments were returned.</ChartMessage>
          )}
        </DashboardPanel>
      </div>
    </div>
  );
};

export default AdminDashboard;
