import { useCallback, useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { api } from "../api";

const SharePage = () => {
  const { token } = useParams();
  const [error, setError] = useState("");
  const [passcode, setPasscode] = useState("");
  const [otp, setOtp] = useState("");
  const [requiresOtp, setRequiresOtp] = useState(false);
  const [loading, setLoading] = useState(true);

  const openDocument = useCallback(async (providedPasscode) => {
    setLoading(true);
    try {
      const { blob, filename } = await api.shareContent(token, providedPasscode || "");
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 60_000);
    } catch (requestError) {
      const message = requestError.message;
      const normalizedMessage = message.toLowerCase();
      setError(message);
      setRequiresOtp(normalizedMessage.includes("otp"));
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    void Promise.resolve().then(() => openDocument(""));
  }, [openDocument]);

  const download = async (event) => {
    event.preventDefault();
    setError("");
    await openDocument(passcode);
  };

  const verifyOtp = async (event) => {
    event.preventDefault();
    setLoading(true);
    setError("");
    try {
      await api.verifyShareOtp(token, otp);
      setRequiresOtp(false);
      await openDocument(passcode);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="flex min-h-screen items-center justify-center p-6">
      <div className="rounded-xl border border-gray-200 bg-white p-8 text-center shadow-sm">
        {error && !requiresOtp && <p role="alert" className="mb-4 text-red-600">{error}</p>}
        {requiresOtp && (
          <form onSubmit={verifyOtp} className="space-y-3">
            <p className="text-gray-600">Enter the six-digit OTP sent to the recipient email.</p>
            <input required pattern="\d{6}" value={otp} onChange={(event) => setOtp(event.target.value)} className="w-full rounded-lg border border-gray-300 px-3 py-2" placeholder="123456" />
            <button className="rounded-lg bg-[#171440] px-4 py-2 text-sm font-semibold text-white">Verify OTP</button>
          </form>
        )}
        {!requiresOtp && error?.toLowerCase().includes("passcode") && (
          <form onSubmit={download} className="space-y-3">
            <p className="text-gray-600">Enter the share passcode if one was required.</p>
            <input type="password" value={passcode} onChange={(event) => setPasscode(event.target.value)} className="w-full rounded-lg border border-gray-300 px-3 py-2" placeholder="Passcode" />
            <button disabled={loading} className="rounded-lg bg-[#171440] px-4 py-2 text-sm font-semibold text-white disabled:opacity-60">Open document</button>
          </form>
        )}
        {!error && !requiresOtp && <p className="text-gray-600">Preparing your secure document...</p>}
      </div>
    </main>
  );
};

export default SharePage;
