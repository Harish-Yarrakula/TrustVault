import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api";

export default function AcceptInvitation() {
  const [searchParams] = useSearchParams();
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const token = searchParams.get("token") || "";

  const submit = async (event) => {
    event.preventDefault();
    setSubmitting(true);
    setError("");
    setMessage("");
    try {
      await api.acceptGuest(token, password);
      setMessage("Invitation accepted. You can now sign in with your email and password.");
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <main className="flex min-h-screen items-center justify-center bg-gray-50 px-4">
      <form onSubmit={submit} className="w-full max-w-md rounded-2xl bg-white p-8 shadow">
        <h1 className="text-2xl font-bold text-gray-900">Accept your invitation</h1>
        <p className="mt-2 text-sm text-gray-500">
          Set a password to activate your TrustVault profile.
        </p>
        {!token && <p className="mt-4 text-sm text-red-600">This invitation link is missing its token.</p>}
        {error && <p role="alert" className="mt-4 text-sm text-red-600">{error}</p>}
        {message && (
          <p role="status" className="mt-4 text-sm text-green-700">
            {message} <Link className="font-semibold underline" to="/auth/login">Sign in</Link>
          </p>
        )}
        {!message && (
          <>
            <label className="mt-6 block text-sm font-semibold text-gray-700" htmlFor="invite-password">
              Password
            </label>
            <input
              id="invite-password"
              type="password"
              minLength={8}
              maxLength={128}
              required
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              className="mt-2 w-full rounded-xl border border-gray-300 px-4 py-3"
            />
            <button
              type="submit"
              disabled={!token || submitting}
              className="mt-6 w-full rounded-xl bg-[#171440] px-4 py-3 text-sm font-semibold text-white disabled:opacity-50"
            >
              {submitting ? "Activating..." : "Activate profile"}
            </button>
          </>
        )}
      </form>
    </main>
  );
}
