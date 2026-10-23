import { useMemo, useState } from "react";
const DocumentLibrary = ({ documents = [], onSelect, onShare, onDownload, onDelete, canShare, error }) => {
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("");
  const [owner, setOwner] = useState("");
  const [date, setDate] = useState("");

  const filteredDocuments = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    return documents.filter((document) => {
      const matchesQuery =
        !normalizedQuery ||
        [document.name, document.owner, document.category, document.content_type].some((value) =>
          String(value || "").toLowerCase().includes(normalizedQuery),
        );
      const ownerMatches = !owner || String(document.owner_id || "").toLowerCase().includes(owner.trim().toLowerCase());
      const dateMatches = !date || String(document.updated_at || document.created_at).startsWith(date);
      return matchesQuery && (!category || document.category === category) && ownerMatches && dateMatches;
    });
  }, [category, date, documents, owner, query]);

  return (
    <div className="mt-6 rounded-xl border border-gray-200 bg-white p-5">
      <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-semibold text-gray-900">Documents</h2>
          <p className="text-sm text-gray-500">
            Only documents available to your account are shown.
          </p>
        </div>
        <div className="flex w-full flex-col gap-2 sm:w-auto sm:flex-row">
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search documents"
            className="rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-[#171440]"
            aria-label="Search documents"
          />
        </div>
        <div className="flex w-full flex-wrap gap-2 border-t border-gray-100 pt-3 sm:w-auto sm:border-0 sm:pt-0">
          <select
            value={category}
            onChange={(event) => setCategory(event.target.value)}
            className="rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-[#171440]"
            aria-label="Filter by category"
          >
            <option value="">All categories</option>
            <option value="Contracts">Contracts</option>
            <option value="Finance">Finance</option>
            <option value="Reports">Reports</option>
            <option value="Policies">Policies</option>
          </select>
          <input
            value={owner}
            onChange={(event) => setOwner(event.target.value)}
            placeholder="Filter by owner"
            className="min-w-36 rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-[#171440]"
            aria-label="Filter by owner"
          />
          <input
            type="date"
            value={date}
            onChange={(event) => setDate(event.target.value)}
            className="rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-[#171440]"
            aria-label="Filter by date"
          />
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[650px] text-left text-sm">
          <thead className="border-b border-gray-200 text-xs uppercase text-gray-500">
            <tr>
              <th className="px-3 py-3">Document</th>
              <th className="px-3 py-3">Owner</th>
              <th className="px-3 py-3">Category</th>
              <th className="px-3 py-3">Updated</th>
              <th className="px-3 py-3">Access</th>
              <th className="px-3 py-3">Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredDocuments.map((document) => (
              <tr key={document.id} className="border-b border-gray-100">
                <td className="px-3 py-4 font-medium text-gray-900">
                  <button type="button" onClick={() => onSelect?.(document)} className="text-left font-medium text-[#171440] hover:underline">
                    {document.name}
                  </button>
                </td>
                <td className="px-3 py-4 text-gray-600">{document.owner_id || "Unknown"}</td>
                <td className="px-3 py-4 text-gray-600">{document.category || "Uncategorized"}</td>
                <td className="px-3 py-4 text-gray-600">
                  {new Date(document.updated_at || document.created_at).toLocaleDateString()}
                </td>
                <td className="px-3 py-4 text-gray-600">Tenant access</td>
                <td className="px-3 py-4">
                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={() => onDownload?.(document)}
                      className="rounded-md bg-[#171440] px-3 py-1.5 text-xs font-semibold text-white hover:opacity-90"
                    >
                      Open
                    </button>
                    {canShare?.(document) && <button
                      type="button"
                      onClick={() => onShare?.(document)}
                      className="rounded-md border border-gray-300 px-3 py-1.5 text-xs font-semibold text-gray-700 hover:bg-gray-50"
                    >
                      Share
                    </button>}
                    {onDelete && (
                      <button
                        type="button"
                        onClick={() => onDelete(document)}
                        className="rounded-md border border-red-200 px-3 py-1.5 text-xs font-semibold text-red-600 hover:bg-red-50"
                      >
                        Delete
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {filteredDocuments.length === 0 && (
        <p className="py-8 text-center text-sm text-gray-500">
          No documents match your search.
        </p>
      )}
      {error && <p role="alert" className="mt-4 text-sm text-red-600">{error}</p>}
    </div>
  );
};

export default DocumentLibrary;
