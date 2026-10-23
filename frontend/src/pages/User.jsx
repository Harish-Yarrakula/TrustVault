import { useEffect, useState } from "react";
import { Navigate } from "react-router-dom";
import AdminView from "./roleviews/AdminView";
import WorkspaceView from "./roleviews/WorkspaceView";
import { api } from "../api";

const User = () => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.me().then(setUser).catch(() => {}).finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="p-8 text-gray-600">Loading workspace...</div>;
  if (!user) return <Navigate to="/auth/login" replace />;
  return user.role === "ADMIN"
    ? <AdminView user={user} />
    : <WorkspaceView user={user} />;
};

export default User;
