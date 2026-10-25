import { useCallback, useEffect, useState } from "react";
import { api, saveDownload } from "../api";

const SharePage = () => {
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [passcode, setPasscode] = useState("");
  const [otp, setOtp] = useState("");
  const [requiresOtp, setRequiresOtp] = useState(false);
  const [loading, setLoading] = useState(true);

  const openDocument = useCallback(async (providedPasscode) => {
    setLoading(true);
    try {
      const { blob, filename } = await api.shareContent(providedPasscode || "");
      saveDownload(blob, filename);
    } catch (requestError) {
      const message = requestError.message;
      const normalizedMessage = message.toLowerCase();
      setError(message);
      setRequiresOtp(normalizedMessage.includes("otp"));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let active = true;
    const fragmentToken = new URLSearchParams(window.location.hash.slice(1)).get("token");
    if (fragmentToken) {
      window.history.replaceState({}, "", `${window.location.pathname}${window.location.search}`);
    }
    const prepareShare = async () => {
      try {
        if (fragmentToken) {
          const session = await api.exchangeShareToken(fragmentToken);
          if (!active) return;
          setRequiresOtp(session.requires_otp);
          if (session.requires_otp) {
            setLoading(false);
            return;
          }
        }
        if (active) await openDocument("");
      } catch (requestError) {
        if (active) {
          setError(requestError.message);
          setLoading(false);
        }
      }
    };
    void prepareShare();
    return () => {
      active = false;
    };
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
    setNotice("");
    try {
      await api.verifyShareOtp(otp);
      setRequiresOtp(false);
      await openDocument(passcode);
    } catch (requestError) {
      setError(
        requestError.status === 401 && requestError.message.toLowerCase().includes("share session")
          ? "This secure share session expired. Reopen the original share link to continue."
          : requestError.message,
      );
    } finally {
      setLoading(false);
    }
  };

  const resendOtp = async () => {
    setLoading(true);
    setError("");
    setNotice("");
    try {
      await api.resendShareOtp();
      setOtp("");
      setNotice("A new verification code was sent to the recipient email.");
    } catch (requestError) {
      setError(
        requestError.status === 401 && requestError.message.toLowerCase().includes("share session")
          ? "This secure share session expired. Reopen the original share link to request another code."
          : requestError.message,
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="flex min-h-screen items-center justify-center p-6">
      <div className="rounded-xl border border-gray-200 bg-white p-8 text-center shadow-sm">
        {error && <p role="alert" className="mb-4 text-red-600">{error}</p>}
        {notice && <p role="status" className="mb-4 text-green-700">{notice}</p>}
        {requiresOtp && (
          <form onSubmit={verifyOtp} className="space-y-3">
            <p className="text-gray-600">Enter the six-digit OTP sent to the recipient email.</p>
            <input required pattern="\d{6}" value={otp} onChange={(event) => setOtp(event.target.value)} className="w-full rounded-lg border border-gray-300 px-3 py-2" placeholder="123456" />
            <button disabled={loading} className="rounded-lg bg-[#171440] px-4 py-2 text-sm font-semibold text-white disabled:opacity-60">Verify OTP</button>
            <button type="button" disabled={loading} onClick={resendOtp} className="ml-3 rounded-lg border border-gray-300 px-4 py-2 text-sm font-semibold text-gray-700 disabled:opacity-60">
              {loading ? "Please wait..." : "Resend code"}
            </button>
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
