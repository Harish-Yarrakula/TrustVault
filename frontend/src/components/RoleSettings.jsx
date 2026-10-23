import { useEffect, useState } from "react";
import { api } from "../api";

const RoleSettings = () => {
  const [users, setUsers] = useState([]);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState("");

  useEffect(() => {
    api.members().then(setUsers).catch((requestError) => setError(requestError.message));
  }, []);

  const updateRole = async (id, role) => {
    try {
      const updated = await api.updateMemberRole(id, role);
      setUsers((current) => current.map((user) => user.id === id ? updated : user));
      setSaved(`Role updated for ${updated.email}.`);
      setError("");
    } catch (requestError) {
      setError(requestError.message);
    }
  };

  return (
    <div className="mt-6 max-w-2xl rounded-xl border border-gray-200 bg-white p-6">
      <h2 className="text-xl font-semibold text-gray-900">Users and roles</h2>
      <p className="mt-1 text-sm text-gray-500">
        Administrators manage the company. Members and external clients receive
        document access independently of their account role.
      </p>
      {error && <p role="alert" className="mt-3 text-sm text-red-600">{error}</p>}
      {saved && <p role="status" className="mt-3 text-sm text-green-700">{saved}</p>}
      <div className="mt-5 divide-y divide-gray-100">
        {users.map((user) => (
          <div
            key={user.email}
            className="flex items-center justify-between gap-4 py-3"
          >
            <span className="text-sm text-gray-700">{user.email}</span>
            <select
              value={user.role}
              onChange={(event) => updateRole(user.id, event.target.value)}
              className="rounded-lg border border-gray-300 px-3 py-2 text-sm"
              aria-label={`Role for ${user.email}`}
            >
              <option value="ADMIN">Administrator</option>
              <option value="MEMBER">Member</option>
              <option value="EXTERNAL_CLIENT">External client</option>
            </select>
          </div>
        ))}
      </div>
    </div>
  );
};

export default RoleSettings;
