const WorkspaceUpdates = ({ notifications = [], documents = [], onOpenDocument, onMarkRead }) => (
  <section className="mx-auto mt-6 w-full max-w-6xl rounded-xl border border-gray-200 bg-white p-5 sm:p-6">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2 className="text-xl font-semibold text-gray-900">Workspace updates</h2>
        <p className="mt-1 text-sm text-gray-500">
          Recent document assignments and important account activity.
        </p>
      </div>
      {notifications.some((notification) => !notification.read_at) && (
        <span className="rounded-full bg-blue-50 px-3 py-1 text-xs font-semibold text-blue-700">
          {notifications.filter((notification) => !notification.read_at).length} new
        </span>
      )}
    </div>

    <div className="mt-4 divide-y divide-gray-100">
      {notifications.slice(0, 8).map((notification) => {
        const assigned = notification.action === "PERMISSION_GRANTED" ||
          (notification.action === "GUEST_INVITED" && Boolean(notification.document_id));
        const document = documents.find((item) => item.id === notification.document_id);
        return (
          <article key={notification.id} className="flex flex-wrap items-center justify-between gap-3 py-4">
            <div className="flex min-w-0 items-start gap-3">
              <span aria-hidden="true" className={`mt-0.5 flex size-9 shrink-0 items-center justify-center rounded-full ${assigned ? "bg-blue-50 text-blue-700" : "bg-gray-100 text-gray-600"}`}>
                {assigned ? "↗" : "•"}
              </span>
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <h3 className="font-medium text-gray-900">
                    {assigned ? "A document was shared with you" : notification.action.replaceAll("_", " ").toLowerCase()}
                  </h3>
                  {!notification.read_at && <span className="rounded-full bg-blue-50 px-2 py-0.5 text-[10px] font-semibold uppercase text-blue-700">New</span>}
                </div>
                <p className="mt-1 truncate text-sm text-gray-600">
                  {notification.document_name
                    ? `${notification.document_name}${notification.actor_name ? ` · shared by ${notification.actor_name}` : ""}`
                    : notification.details || "There is a new update in your workspace."}
                </p>
                <time className="mt-1 block text-xs text-gray-500" dateTime={notification.occurred_at}>
                  {new Date(notification.occurred_at).toLocaleString()}
                </time>
              </div>
            </div>
            <div className="flex shrink-0 gap-2">
              {document && (
                <button type="button" onClick={() => onOpenDocument(document)} className="rounded-lg bg-[#171440] px-3 py-2 text-xs font-semibold text-white hover:opacity-90">
                  Open document
                </button>
              )}
              {!notification.read_at && (
                <button type="button" onClick={() => onMarkRead(notification.id)} className="rounded-lg border border-gray-300 px-3 py-2 text-xs font-semibold text-gray-700 hover:bg-gray-50">
                  Mark read
                </button>
              )}
            </div>
          </article>
        );
      })}
      {notifications.length === 0 && (
        <p className="py-6 text-center text-sm text-gray-500">You’re all caught up. New document assignments will appear here.</p>
      )}
    </div>
  </section>
);

export default WorkspaceUpdates;
