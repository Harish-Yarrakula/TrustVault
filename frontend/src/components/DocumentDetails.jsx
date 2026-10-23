import PermissionManager from "./PermissionManager";

const DocumentDetails = ({ document, owner, onBack, canManage }) => (
  <div className="mt-6">
    <button type="button" onClick={onBack} className="mb-4 text-sm font-semibold text-[#171440] hover:underline">
      ← Back to documents
    </button>
    <div className="rounded-xl border border-gray-200 bg-white p-6">
      <h2 className="text-2xl font-semibold text-gray-900">{document.name}</h2>
      <dl className="mt-4 grid gap-4 text-sm sm:grid-cols-2">
        <div><dt className="text-gray-500">Owner</dt><dd className="font-medium">{owner?.full_name || owner?.email || document.owner_id}</dd></div>
        <div><dt className="text-gray-500">Owner email</dt><dd className="font-medium">{owner?.email || "Unknown"}</dd></div>
        <div><dt className="text-gray-500">Type</dt><dd className="font-medium">{document.content_type}</dd></div>
        <div><dt className="text-gray-500">Updated</dt><dd className="font-medium">{new Date(document.updated_at || document.created_at).toLocaleString()}</dd></div>
      </dl>
    </div>
    {canManage ? <PermissionManager document={document} /> : (
      <p className="mt-4 rounded-xl border border-gray-200 bg-white p-5 text-sm text-gray-600">
        You have access to this document, but only its owner can manage sharing.
      </p>
    )}
  </div>
);

export default DocumentDetails;
