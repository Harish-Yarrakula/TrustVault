import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, setAccessToken } from "../api";

export default function MfaSetup() {
  const navigate = useNavigate();
  const [secret, setSecret] = useState("");
  const [code, setCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.setupMfa()
      .then((setup) => setSecret(setup.secret))
      .catch((requestError) => setError(requestError.message))
      .finally(() => setLoading(false));
  }, []);

  const confirm = async (event) => {
    event.preventDefault();
    setError("");
    try {
      const result = await api.confirmMfa(code.trim());
      setAccessToken(result.access_token);
      setRecoveryCodes(result.recovery_codes);
    } catch (requestError) {
      setError(requestError.message);
    }
  };

  const finish = () => navigate("/dashboard");

  return (
    <main className="flex min-h-screen items-center justify-center bg-gray-50 px-4 py-10">
      <section className="w-full max-w-xl rounded-2xl bg-white p-8 shadow">
        <h1 className="text-2xl font-bold text-gray-900">Set up administrator MFA</h1>
        {loading && <p className="mt-4 text-sm text-gray-600">Preparing secure setup...</p>}
        {error && <p role="alert" className="mt-4 text-sm text-red-600">{error}</p>}
        {!loading && !recoveryCodes.length && secret && (
          <form onSubmit={confirm}>
            <p className="mt-3 text-sm text-gray-600">
              Add this key to an authenticator app, then enter its current six-digit code.
            </p>
            <code className="mt-4 block break-all rounded-lg bg-gray-100 p-4 text-sm font-semibold tracking-widest">
              {secret}
            </code>
            <label htmlFor="mfa-setup-code" className="mt-5 block text-sm font-semibold text-gray-700">
              Authenticator code
            </label>
            <input
              id="mfa-setup-code"
              autoComplete="one-time-code"
              inputMode="numeric"
              pattern="\d{6}"
              minLength={6}
              maxLength={6}
              required
              value={code}
              onChange={(event) => setCode(event.target.value)}
              className="mt-2 w-full rounded-xl border border-gray-300 px-4 py-3"
            />
            <button className="mt-5 w-full rounded-xl bg-[#171440] px-4 py-3 text-sm font-semibold text-white">
              Enable MFA
            </button>
          </form>
        )}
        {recoveryCodes.length > 0 && (
          <div className="mt-4">
            <p className="text-sm text-gray-700">
              Save these recovery codes somewhere secure. Each code works once, and they cannot be shown again.
            </p>
            <ul className="mt-4 grid grid-cols-2 gap-2 rounded-lg bg-gray-100 p-4 font-mono text-sm">
              {recoveryCodes.map((recoveryCode) => <li key={recoveryCode}>{recoveryCode}</li>)}
            </ul>
            <button
              type="button"
              onClick={finish}
              className="mt-5 w-full rounded-xl bg-[#171440] px-4 py-3 text-sm font-semibold text-white"
            >
              I saved the codes — continue
            </button>
          </div>
        )}
      </section>
    </main>
  );
}
