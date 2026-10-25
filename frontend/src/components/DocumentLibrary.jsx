import { useMemo, useState } from "react";

const defaultCategories = ["Contracts", "Finance", "Reports", "Policies"];

const DocumentLibrary = ({
  documents = [],
  rootName = "Company workspace",
  onSelect,
  onShare,
  onDownload,
  onDelete,
  canShare,
  error,
}) => {
  const [query, setQuery] = useState("");
  const [owner, setOwner] = useState("");
  const [date, setDate] = useState("");
  const [openCategory, setOpenCategory] = useState(null);
  const normalizedQuery = query.trim().toLowerCase();
  const categories = useMemo(
    () => [...new Set([
      ...defaultCategories,
      ...documents.map((document) => document.category || "Uncategorized"),
    ])],
    [documents],
  );
  const folderDocuments = useMemo(() => documents.filter((document) => {
    const category = document.category || "Uncategorized";
    const matchesCategory = !openCategory || category === openCategory;
    const matchesQuery = !normalizedQuery ||
      [document.name, document.owner, document.content_type].some((value) =>
        String(value || "").toLowerCase().includes(normalizedQuery),
      );
    const ownerMatches = !owner ||
      String(document.owner_id || "").toLowerCase().includes(owner.trim().toLowerCase());
    const documentDate = document.updated_at || document.created_at;
    const dateMatches = !date || String(documentDate).startsWith(date);
    return matchesCategory && matchesQuery && ownerMatches && dateMatches;
  }), [date, documents, normalizedQuery, openCategory, owner]);
  const searchResultsAtRoot = !openCategory && normalizedQuery
    ? documents.filter((document) =>
      [document.name, document.category, document.content_type].some((value) =>
        String(value || "").toLowerCase().includes(normalizedQuery),
      ),
    )
    : [];

  return (
    <section className="mx-auto mt-6 w-full max-w-6xl rounded-xl border border-gray-200 bg-white p-4 sm:p-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="mb-2 flex items-center gap-2 text-sm text-gray-500">
            <span aria-hidden="true">⌂</span>
            {openCategory ? (
              <>
                <button type="button" onClick={() => setOpenCategory(null)} className="hover:text-[#171440] hover:underline">
                  {rootName}
                </button>
                <span aria-hidden="true">/</span>
                <span className="font-medium text-gray-700">{openCategory}</span>
              </>
            ) : (
              <span className="font-medium text-gray-700">{rootName}</span>
            )}
          </div>
          <h2 className="text-xl font-semibold text-gray-900">
            {openCategory || rootName}
          </h2>
          <p className="mt-1 text-sm text-gray-500">
            {openCategory
              ? `${folderDocuments.length} document${folderDocuments.length === 1 ? "" : "s"} in this folder`
              : "Browse your company folders and documents."}
          </p>
        </div>
        <label className="w-full sm:w-72">
          <span className="sr-only">Search documents</span>
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search documents"
            className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-[#171440]"
            aria-label="Search documents"
          />
        </label>
      </div>

      {error && <p role="alert" className="mt-4 rounded-lg bg-red-50 p-3 text-sm text-red-700">{error}</p>}

      {!openCategory && (
        <div className="mt-6">
          <h3 className="mb-3 text-sm font-semibold uppercase tracking-wide text-gray-500">Folders</h3>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {categories.map((folder) => {
              const count = documents.filter((document) =>
                (document.category || "Uncategorized") === folder,
              ).length;
              return (
                <button
                  key={folder}
                  type="button"
                  onClick={() => setOpenCategory(folder)}
                  className="flex items-center gap-4 rounded-xl border border-gray-200 p-4 text-left transition hover:border-[#171440]/40 hover:bg-gray-50"
                  aria-label={`Open ${folder} folder, ${count} documents`}
                >
                  <span aria-hidden="true" className="text-3xl">📁</span>
                  <span className="min-w-0">
                    <span className="block truncate font-semibold text-gray-900">{folder}</span>
                    <span className="mt-1 block text-sm text-gray-500">
                      {count} document{count === 1 ? "" : "s"}
                    </span>
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      )}

      {openCategory && (
        <>
          <div className="mt-5 flex flex-wrap gap-2 border-t border-gray-100 pt-4">
            <input
              value={owner}
              onChange={(event) => setOwner(event.target.value)}
              placeholder="Filter by owner"
              className="min-w-36 rounded-lg border border-gray-300 px-3 py-2 text-sm"
              aria-label="Filter by owner"
            />
            <input
              type="date"
              value={date}
              onChange={(event) => setDate(event.target.value)}
              className="rounded-lg border border-gray-300 px-3 py-2 text-sm"
              aria-label="Filter by date"
            />
          </div>
          <div className="mt-4 overflow-x-auto">
            <table className="w-full min-w-[620px] text-left text-sm">
              <thead className="border-b border-gray-200 text-xs uppercase text-gray-500">
                <tr>
                  <th className="px-3 py-3">Document</th>
                  <th className="px-3 py-3">Owner</th>
                  <th className="px-3 py-3">Updated</th>
                  <th className="px-3 py-3">Access</th>
                  <th className="px-3 py-3">Actions</th>
                </tr>
              </thead>
              <tbody>
                {folderDocuments.map((document) => (
                  <tr key={document.id} className="border-b border-gray-100">
                    <td className="px-3 py-4 font-medium text-gray-900">
                      <button type="button" onClick={() => onSelect?.(document)} className="text-left font-medium text-[#171440] hover:underline">
                        {document.name}
                      </button>
                    </td>
                    <td className="px-3 py-4 text-gray-600">{document.owner_id || "Unknown"}</td>
                    <td className="px-3 py-4 text-gray-600">
                      {new Date(document.updated_at || document.created_at).toLocaleDateString()}
                    </td>
                    <td className="px-3 py-4 text-gray-600">Granted access</td>
                    <td className="px-3 py-4">
                      <div className="flex gap-2">
                        <button
                          type="button"
                          onClick={() => onDownload?.(document)}
                          className="rounded-md bg-[#171440] px-3 py-1.5 text-xs font-semibold text-white hover:opacity-90"
                        >
                          Open
                        </button>
                        {canShare?.(document) && (
                          <button
                            type="button"
                            onClick={() => onShare?.(document)}
                            className="rounded-md border border-gray-300 px-3 py-1.5 text-xs font-semibold text-gray-700 hover:bg-gray-50"
                          >
                            Share
                          </button>
                        )}
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
          {folderDocuments.length === 0 && (
            <p className="py-8 text-center text-sm text-gray-500">
              {normalizedQuery || owner || date
                ? "No documents match your filters."
                : "This folder is empty."}
            </p>
          )}
        </>
      )}

      {!openCategory && normalizedQuery && (
        <div className="mt-6 border-t border-gray-100 pt-5">
          <h3 className="mb-3 text-sm font-semibold text-gray-700">Matching documents</h3>
          {searchResultsAtRoot.length ? (
            <ul className="divide-y divide-gray-100">
              {searchResultsAtRoot.map((document) => (
                <li key={document.id} className="flex items-center justify-between gap-4 py-3">
                  <button type="button" onClick={() => {
                    setOpenCategory(document.category || "Uncategorized");
                    setQuery(document.name);
                  }} className="min-w-0 text-left hover:underline">
                    <span className="block truncate font-medium text-[#171440]">{document.name}</span>
                    <span className="text-xs text-gray-500">{document.category || "Uncategorized"}</span>
                  </button>
                  <button type="button" onClick={() => onDownload?.(document)} className="rounded-md bg-[#171440] px-3 py-1.5 text-xs font-semibold text-white">
                    Open
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-gray-500">No matching documents.</p>
          )}
        </div>
      )}
    </section>
  );
};

export default DocumentLibrary;
