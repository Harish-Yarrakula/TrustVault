import { useEffect, useState } from "react";
import { Navigate } from "react-router-dom";
import AdminView from "./roleviews/AdminView";
import WorkspaceView from "./roleviews/WorkspaceView";
import { api } from "../api";

const User = () => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    api.me()
      .then(setUser)
      .catch((requestError) => {
        if (requestError.status !== 401) setError(requestError.message);
      })
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="p-8 text-gray-600">Loading workspace...</div>;
  if (error) {
    return (
      <div role="alert" className="p-8 text-red-700">
        Unable to load the workspace: {error}
      </div>
    );
  }
  if (!user) return <Navigate to="/auth/login" replace />;
  return user.role === "ADMIN"
    ? <AdminView user={user} />
    : <WorkspaceView user={user} />;
};

export default User;
