import { useEffect, useState } from "react";
import { api } from "../api";

const PermissionManager = ({ document }) => {
  const [grants, setGrants] = useState([]);
  const [members, setMembers] = useState([]);
  const [email, setEmail] = useState("");
  const [access, setAccess] = useState("READ");
  const [recipientType, setRecipientType] = useState("member");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    if (!document?.id) return;
    Promise.all([api.permissions(document.id), api.members()])
      .then(([permissions, companyMembers]) => {
        setGrants(
          permissions.map((permission) => ({
            ...permission,
            email: companyMembers.find((member) => member.id === permission.user_id)?.email ||
              permission.user_id,
          })),
        );
        setMembers(companyMembers);
      })
      .catch((requestError) => setError(requestError.message));
  }, [document?.id]);

  const grantAccess = async (event) => {
    event.preventDefault();
    try {
      if (recipientType === "member") {
        const member = members.find((item) => item.email === email);
        if (!member) {
          setError("Choose a registered company member.");
          return;
        }
        const permission = await api.grantPermission(document.id, {
          user_id: member.id,
          permission_level: access,
        });
        setGrants((current) => [
          ...current.filter((item) => item.user_id !== member.id),
          { ...permission, email: member.email },
        ]);
        setMessage(`Access granted to ${member.email}.`);
      } else {
        await api.inviteGuest({
          email,
          document_id: document.id,
          permission_level: access,
        });
        setMessage(`Invitation sent to ${email}. They can activate their profile from the email.`);
      }
      setEmail("");
      setError("");
    } catch (requestError) {
      setError(requestError.message);
    }
  };

  const revokeAccess = async (grant) => {
    try {
      await api.revokePermission(document.id, grant.id);
      setGrants((current) => current.filter((item) => item.id !== grant.id));
      setMessage("Access revoked.");
    } catch (requestError) {
      setError(requestError.message);
    }
  };

  return (
    <div className="mt-6 max-w-3xl rounded-xl border border-gray-200 bg-white p-6">
      <h2 className="text-xl font-semibold text-gray-900">Manage access</h2>
      <p className="mt-1 text-sm text-gray-500">
        {document?.name || "Select a document"} · Changes take effect immediately.
      </p>
      {error && <p role="alert" className="mt-3 text-sm text-red-600">{error}</p>}
      <form onSubmit={grantAccess} className="mt-5 flex flex-wrap gap-3">
        <select
          value={recipientType}
          onChange={(event) => {
            setRecipientType(event.target.value);
            setEmail("");
          }}
          className="min-w-56 flex-1 rounded-lg border border-gray-300 px-3 py-2 text-sm"
          aria-label="Access recipient type"
        >
          <option value="member">Registered company member</option>
          <option value="invite">Invite by email</option>
        </select>
        {recipientType === "member" ? (
          <select
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            required
            className="min-w-56 flex-1 rounded-lg border border-gray-300 px-3 py-2 text-sm"
            aria-label="Company member"
          >
            <option value="">Choose a company member</option>
            {members.map((member) => (
              <option key={member.id} value={member.email}>{member.email}</option>
            ))}
          </select>
        ) : (
          <input
            type="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            placeholder="person@company.com"
            required
            className="min-w-56 flex-1 rounded-lg border border-gray-300 px-3 py-2 text-sm"
            aria-label="Invitation email"
          />
        )}
        <select
          value={access}
          onChange={(event) => setAccess(event.target.value)}
          className="rounded-lg border border-gray-300 px-3 py-2 text-sm"
          aria-label="Permission level"
        >
          <option value="READ">Read</option>
          <option value="WRITE">Write</option>
        </select>
        <button
          type="submit"
          className="rounded-lg bg-[#171440] px-4 py-2 text-sm font-semibold text-white"
        >
          {recipientType === "member" ? "Grant access" : "Send invitation"}
        </button>
      </form>
      {message && <p className="mt-3 text-sm text-green-700">{message}</p>}
      <div className="mt-5 divide-y divide-gray-100">
        {grants.map((grant) => (
          <div
            key={grant.id}
            className="flex items-center justify-between gap-4 py-3 text-sm"
          >
            <span className="text-gray-700">{grant.email}</span>
            <div className="flex items-center gap-3">
              <span className="rounded-full bg-gray-100 px-3 py-1 text-xs font-semibold text-gray-700">
                {grant.permission_level || grant.access}
              </span>
              <button
                type="button"
                onClick={() => revokeAccess(grant)}
                className="text-xs font-semibold text-red-600 hover:underline"
              >
                Revoke
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default PermissionManager;
