import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { api, setAccessToken } from "../api";

const API_URL = import.meta.env.PROD ? "" : (import.meta.env.VITE_API_URL || "http://localhost:8000");

const features = [
  {
    tag: "Enterprise Security",
    title: "End-to-End Protection",
    description:
      "SOC2-ready authentication, role-based access controls, and automated compliance tracking built into every tier from day one.",
  },
  {
    tag: "Intelligent Analytics",
    title: "Real-Time Insights",
    description:
      "Gain complete visibility into customer conversions, performance bottlenecks, and retention metrics with interactive live dashboards.",
  },
];

export default function AuthPage() {
  const navigate = useNavigate();
  const [isSignUp, setIsSignUp] = useState(false);
  const [activeSlide, setActiveSlide] = useState(0);
  const [showPassword, setShowPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const [successMessage, setSuccessMessage] = useState("");
  const [mfaChallengeToken, setMfaChallengeToken] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [mfaError, setMfaError] = useState("");
  const [mfaSubmitting, setMfaSubmitting] = useState(false);

  // State for the Social Login "Coming Soon" popup
  const [comingSoonProvider, setComingSoonProvider] = useState(null);

  const [formData, setFormData] = useState({
    fullName: "",
    companyName: "",
    role: "MEMBER",
    email: "",
    password: "",
    confirmPassword: "",
    rememberMe: false,
    agreeTerms: false,
  });

  // Close modal when pressing Escape key
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === "Escape") setComingSoonProvider(null);
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    const email = formData.email.trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      setErrorMessage("Enter a valid email address.");
      return;
    }
    if (isSignUp && !formData.fullName.trim()) {
      setErrorMessage("Enter your full name.");
      return;
    }
    if (formData.password.length < 8 || formData.password.length > 128) {
      setErrorMessage("Password must be between 8 and 128 characters.");
      return;
    }
    if (isSignUp && formData.password !== formData.confirmPassword) {
      setErrorMessage("Passwords do not match.");
      return;
    }

    setIsSubmitting(true);
    setErrorMessage("");
    setSuccessMessage("");

    try {
      let response;
      if (isSignUp) {
        response = await fetch(`${API_URL}/api/auth/register`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Request-ID": crypto.randomUUID(),
          },
          credentials: "include",
          signal: AbortSignal.timeout(10000),
          body: JSON.stringify({
          full_name: formData.fullName.trim(),
          email,
          password: formData.password,
          role: formData.role,
            ...(formData.companyName.trim()
              ? { company_name: formData.companyName.trim() }
              : {}),
          }),
        });
      } else {
        const body = new URLSearchParams();
        body.set("username", email);
        body.set("password", formData.password);

        response = await fetch(`${API_URL}/api/auth/login`, {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Request-ID": crypto.randomUUID(),
          },
          credentials: "include",
          signal: AbortSignal.timeout(10000),
          body,
        });
      }

      const contentType = response.headers.get("Content-Type")?.toLowerCase() || "";
      if (!contentType.includes("application/json") && !contentType.includes("+json")) {
        throw new Error("The API returned a web page instead of JSON. Check VITE_API_URL and the Netlify API proxy rules.");
      }
      const data = await response.json();
      if (!response.ok) {
        const detail = Array.isArray(data.detail)
          ? data.detail.map((item) => item.msg).join(" ")
          : data.detail;
        throw new Error(detail || "Authentication failed. Please try again.");
      }

      if (isSignUp) {
        setSuccessMessage("Account created. Sign in to continue.");
        setIsSignUp(false);
        setFormData((current) => ({
          ...current,
          password: "",
          confirmPassword: "",
        }));
      } else {
        if (data.mfa_required) {
          setMfaChallengeToken(data.challenge_token);
          return;
        }
        setAccessToken(data.access_token);
        if (data.mfa_setup_required) {
          navigate("/auth/mfa-setup");
          return;
        }
        navigate("/dashboard");
      }
    } catch (error) {
      setErrorMessage(
        error instanceof TypeError
          ? "Unable to reach the server. Please try again."
          : error.message,
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  const verifyMfa = async (event) => {
    event.preventDefault();
    setMfaSubmitting(true);
    setMfaError("");
    try {
      const data = await api.verifyMfaChallenge(mfaChallengeToken, mfaCode.trim());
      setAccessToken(data.access_token);
      navigate("/dashboard");
    } catch (error) {
      setMfaError(error.message);
    } finally {
      setMfaSubmitting(false);
    }
  };

  if (mfaChallengeToken) {
    return (
      <main className="flex min-h-screen items-center justify-center bg-gray-50 px-4">
        <form onSubmit={verifyMfa} className="w-full max-w-md rounded-2xl bg-white p-8 shadow">
          <h1 className="text-2xl font-bold text-gray-900">Verify your identity</h1>
          <p className="mt-2 text-sm text-gray-600">
            Enter your authenticator code or a one-time recovery code.
          </p>
          {mfaError && <p role="alert" className="mt-4 text-sm text-red-600">{mfaError}</p>}
          <label htmlFor="mfa-login-code" className="mt-6 block text-sm font-semibold text-gray-700">
            Verification code
          </label>
          <input
            id="mfa-login-code"
            autoComplete="one-time-code"
            required
            minLength={6}
            maxLength={32}
            value={mfaCode}
            onChange={(event) => setMfaCode(event.target.value)}
            className="mt-2 w-full rounded-xl border border-gray-300 px-4 py-3"
          />
          <button
            type="submit"
            disabled={mfaSubmitting}
            className="mt-6 w-full rounded-xl bg-[#171440] px-4 py-3 text-sm font-semibold text-white disabled:opacity-50"
          >
            {mfaSubmitting ? "Verifying..." : "Continue"}
          </button>
        </form>
      </main>
    );
  }

  return (
    <section className="relative py-20 lg:py-10 overflow-hidden bg-white text-gray-900 font-sans">
      <div className="container px-4 mx-auto max-w-7xl">
        <div className="max-w-7xl mx-auto">
          <div className="flex flex-wrap -mx-4 xl:items-center">
            
            {/* Left Column: Visual Slider & Features */}
            <div className="w-full lg:w-1/2 xl:w-3/5 px-4 order-last lg:order-first">
              <div className="relative max-w-xl mx-auto lg:mx-0 lg:max-w-3xl h-[600px] lg:h-[720px] rounded-3xl overflow-hidden shadow-2xl">
                <img
                  className="block w-full h-full object-cover rounded-3xl"
                  src={
                    isSignUp
                      ? "https://images.unsplash.com/photo-1522071820081-009f0129c71c?auto=format&fit=crop&w=1200&q=80"
                      : "https://images.unsplash.com/photo-1534528741775-53994a69daeb?auto=format&fit=crop&w=1200&q=80"
                  }
                  alt="Authentication background"
                />

                {/* Glassmorphism Feature Card Overlay */}
                <div className="absolute bottom-0 w-full left-0 p-4 sm:p-6 z-10">
                  <div className="p-6 sm:p-10 backdrop-blur-md bg-black/40 border border-white/10 rounded-3xl">
                    <div className="overflow-hidden">
                      <div
                        className="flex transition-transform duration-500 ease-in-out"
                        style={{
                          transform: `translateX(-${activeSlide * 100}%)`,
                        }}
                      >
                        {features.map((item, idx) => (
                          <div key={idx} className="flex-shrink-0 w-full">
                            <span className="inline-block px-3 py-1 mb-2 text-xs font-semibold tracking-wider uppercase text-orange-300 bg-orange-950/60 border border-orange-500/20 rounded-full">
                              {item.tag}
                            </span>
                            <h5 className="text-2xl sm:text-3xl text-white font-bold mb-2">
                              {item.title}
                            </h5>
                            <p className="max-w-xl text-base sm:text-lg text-gray-200 font-medium leading-relaxed mb-6">
                              {item.description}
                            </p>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Slider Indicator Dots */}
                    <div className="flex items-center space-x-2 pt-2">
                      {features.map((_, idx) => (
                        <button
                          key={idx}
                          type="button"
                          onClick={() => setActiveSlide(idx)}
                          aria-label={`Go to slide ${idx + 1}`}
                          className={`h-1.5 transition-all duration-300 rounded-full cursor-pointer ${
                            activeSlide === idx
                              ? "w-8 bg-orange-500"
                              : "w-4 bg-white/50 hover:bg-white"
                          }`}
                        />
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Right Column: Dynamic Form (Sign In / Sign Up) */}
            <div className="w-full lg:w-1/2 xl:w-2/5 px-4 mb-16 lg:mb-0">
              <div className="max-w-md lg:py-12 mx-auto lg:mr-0">
                
                {/* Segmented Tab Switcher */}
                <div className="flex p-1 mb-8 bg-gray-100 rounded-2xl border border-gray-200">
                  <button
                    type="button"
                    onClick={() => setIsSignUp(false)}
                    className={`w-1/2 py-2.5 text-sm font-semibold rounded-xl transition-all duration-200 ${
                      !isSignUp
                        ? "bg-white text-gray-900 shadow-sm"
                        : "text-gray-500 hover:text-gray-900"
                    }`}
                  >
                    Sign In
                  </button>
                  <button
                    type="button"
                    onClick={() => setIsSignUp(true)}
                    className={`w-1/2 py-2.5 text-sm font-semibold rounded-xl transition-all duration-200 ${
                      isSignUp
                        ? "bg-white text-gray-900 shadow-sm"
                        : "text-gray-500 hover:text-gray-900"
                    }`}
                  >
                    Sign Up
                  </button>
                </div>

                {/* Heading & Subtext */}
                <h3 className="text-3xl sm:text-4xl text-gray-900 font-bold tracking-tight mb-3">
                  {isSignUp ? "Create your account" : "Sign in to your account"}
                </h3>
                <p className="text-base text-gray-500 mb-8">
                  {isSignUp
                    ? "Start your journey with us."
                    : "Greetings on your return! We kindly request you to enter your details."}
                </p>

                {/* Social Login Buttons with Popup Triggers */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-6">
                  {/* Google Button */}
                  <button
                    type="button"
                    onClick={() => setComingSoonProvider("Google")}
                    className="inline-flex py-3 px-4 items-center justify-center rounded-xl border border-gray-200 hover:border-gray-400 hover:bg-gray-50 transition-colors cursor-pointer"
                  >
                    <svg className="w-5 h-5" viewBox="0 0 24 24">
                      <path
                        fill="#4285F4"
                        d="M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v3.9h6.6c-.29 1.53-1.14 2.82-2.4 3.68v3.05h3.88c2.27-2.09 3.66-5.17 3.66-8.56z"
                      />
                      <path
                        fill="#34A853"
                        d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3.05c-1.08.72-2.45 1.16-4.05 1.16-3.11 0-5.74-2.11-6.68-4.96H1.21v3.15C3.18 21.88 7.31 24 12 24z"
                      />
                      <path
                        fill="#FBBC05"
                        d="M5.32 14.24A7.16 7.16 0 0 1 4.9 12c0-.79.13-1.57.38-2.31V6.54H1.21A11.94 11.94 0 0 0 0 12c0 1.92.45 3.74 1.21 5.37l4.11-3.13z"
                      />
                      <path
                        fill="#EA4335"
                        d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.43-3.43C17.95 1.19 15.24 0 12 0 7.31 0 3.18 2.12 1.21 5.54l4.11 3.13c.94-2.85 3.57-4.92 6.68-4.92z"
                      />
                    </svg>
                    <span className="ml-3 text-sm font-semibold text-gray-700">
                      Google
                    </span>
                  </button>

                  {/* Apple Button */}
                  <button
                    type="button"
                    onClick={() => setComingSoonProvider("Apple")}
                    className="inline-flex py-3 px-4 items-center justify-center rounded-xl border border-gray-200 hover:border-gray-400 hover:bg-gray-50 transition-colors cursor-pointer"
                  >
                    <svg
                      className="w-5 h-5 text-black"
                      fill="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.81-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M15.97 6.37c.63-.78 1.06-1.85.94-2.94-.91.04-2.03.61-2.69 1.39-.58.67-1.09 1.76-.95 2.81 1.02.08 2.07-.5 2.7-1.26z" />
                    </svg>
                    <span className="ml-3 text-sm font-semibold text-gray-700">
                      Apple
                    </span>
                  </button>
                </div>

                {/* Divider */}
                <div className="flex mb-6 items-center">
                  <div className="w-full h-px bg-gray-200" />
                  <span className="mx-4 text-xs font-semibold text-gray-400 uppercase tracking-wider">
                    Or
                  </span>
                  <div className="w-full h-px bg-gray-200" />
                </div>

                {errorMessage && (
                  <p role="alert" className="mb-4 rounded-xl bg-red-50 px-4 py-3 text-sm text-red-700">
                    {errorMessage}
                  </p>
                )}
                {successMessage && (
                  <p role="status" className="mb-4 rounded-xl bg-green-50 px-4 py-3 text-sm text-green-700">
                    {successMessage}
                  </p>
                )}

                {/* Dynamic Form */}
                <form onSubmit={handleSubmit}>
                  {/* Company Name (Sign Up only) */}
                  {isSignUp && (
                    <>
                    <div className="mb-4">
                      <label className="mb-2 block text-sm font-semibold text-gray-900" htmlFor="fullName">
                        Full name
                      </label>
                      <input
                        id="fullName"
                        type="text"
                        required
                        placeholder="Jane Doe"
                        value={formData.fullName}
                        onChange={(e) => setFormData({ ...formData, fullName: e.target.value })}
                        className="w-full rounded-xl border border-gray-200 px-4 py-3 text-sm focus:border-orange-900 focus:outline-none"
                      />
                    </div>
                    <div className="mb-4">
                      <label
                        className="block mb-2 text-sm text-gray-900 font-semibold"
                        htmlFor="companyName"
                      >
                        Company Name <span className="font-normal text-gray-500">(optional)</span>
                      </label>
                      <input
                        id="companyName"
                        type="text"
                        placeholder="Acme Corporation"
                        value={formData.companyName}
                        onChange={(e) =>
                          setFormData({ ...formData, companyName: e.target.value })
                        }
                        className="w-full py-3 px-4 text-sm text-gray-900 placeholder-gray-400 border border-gray-200 rounded-xl focus:border-orange-900 focus:ring-1 focus:ring-orange-900 focus:outline-none transition-all"
                      />
                    </div>
                    <div className="mb-4">
                      <label className="mb-2 block text-sm font-semibold text-gray-900" htmlFor="role">
                        Account role
                      </label>
                      <select
                        id="role"
                        value={formData.role}
                        onChange={(e) => setFormData({ ...formData, role: e.target.value })}
                        className="w-full rounded-xl border border-gray-200 px-4 py-3 text-sm focus:border-orange-900 focus:outline-none"
                      >
                        <option value="MEMBER">Member</option>
                        <option value="EXTERNAL_CLIENT">External client</option>
                      </select>
                    </div>
                    </>
                  )}

                  {/* Email Field */}
                  <div className="mb-4">
                    <label
                      className="block mb-2 text-sm text-gray-900 font-semibold"
                      htmlFor="email"
                    >
                      {isSignUp ? "Work Email" : "Email"}
                    </label>
                    <input
                      id="email"
                      type="email"
                      autoComplete="email"
                      required
                      placeholder="Johndev@mail.com"
                      value={formData.email}
                      onChange={(e) =>
                        setFormData({ ...formData, email: e.target.value })
                      }
                      className="w-full py-3 px-4 text-sm text-gray-900 placeholder-gray-400 border border-gray-200 rounded-xl focus:border-orange-900 focus:ring-1 focus:ring-orange-900 focus:outline-none transition-all"
                    />
                  </div>

                  {/* Password Field */}
                  <div className="mb-4">
                    <div className="flex mb-2 items-center justify-between">
                      <label
                        className="block text-sm text-gray-900 font-semibold"
                        htmlFor="password"
                      >
                        Password
                      </label>
                      {!isSignUp && (
                        <a
                          href="#"
                          className="inline-block text-xs font-semibold text-orange-900 hover:text-orange-700 transition-colors"
                        >
                          Forgot password?
                        </a>
                      )}
                    </div>
                    <div className="relative">
                      <input
                        id="password"
                        type={showPassword ? "text" : "password"}
                        autoComplete={isSignUp ? "new-password" : "current-password"}
                        required
                        placeholder={
                          isSignUp
                            ? "Create password (min. 8 characters)"
                            : "Enter your password"
                        }
                        value={formData.password}
                        onChange={(e) =>
                          setFormData({ ...formData, password: e.target.value })
                        }
                        className="w-full py-3 pl-4 pr-11 text-sm text-gray-900 placeholder-gray-400 border border-gray-200 rounded-xl focus:border-orange-900 focus:ring-1 focus:ring-orange-900 focus:outline-none transition-all"
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        aria-label={
                          showPassword ? "Hide password" : "Show password"
                        }
                        className="absolute top-1/2 right-3 -translate-y-1/2 text-gray-400 hover:text-gray-700 transition-colors cursor-pointer"
                      >
                        {showPassword ? (
                          <svg
                            className="w-5 h-5"
                            fill="none"
                            stroke="currentColor"
                            viewBox="0 0 24 24"
                          >
                            <path
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              strokeWidth="2"
                              d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l18 18"
                            />
                          </svg>
                        ) : (
                          <svg
                            className="w-5 h-5"
                            fill="none"
                            stroke="currentColor"
                            viewBox="0 0 24 24"
                          >
                            <path
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              strokeWidth="2"
                              d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"
                            />
                            <path
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              strokeWidth="2"
                              d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"
                            />
                          </svg>
                        )}
                      </button>
                    </div>
                  </div>

                  {/* Confirm Password (Sign Up only) */}
                  {isSignUp && (
                    <div className="mb-5">
                      <label
                        className="block mb-2 text-sm text-gray-900 font-semibold"
                        htmlFor="confirmPassword"
                      >
                        Confirm Password
                      </label>
                      <input
                        id="confirmPassword"
                        type={showPassword ? "text" : "password"}
                        autoComplete="new-password"
                        required
                        placeholder="Repeat your password"
                        value={formData.confirmPassword}
                        onChange={(e) =>
                          setFormData({
                            ...formData,
                            confirmPassword: e.target.value,
                          })
                        }
                        className="w-full py-3 px-4 text-sm text-gray-900 placeholder-gray-400 border border-gray-200 rounded-xl focus:border-orange-900 focus:ring-1 focus:ring-orange-900 focus:outline-none transition-all"
                      />
                    </div>
                  )}

                  {/* Remember Me OR Terms Checkbox */}
                  {!isSignUp ? (
                    <div className="flex mb-6 items-center">
                      <input
                        id="rememberMe"
                        type="checkbox"
                        checked={formData.rememberMe}
                        onChange={(e) =>
                          setFormData({
                            ...formData,
                            rememberMe: e.target.checked,
                          })
                        }
                        className="w-4 h-4 text-orange-900 border-gray-300 rounded focus:ring-orange-900 cursor-pointer"
                      />
                      <label
                        htmlFor="rememberMe"
                        className="ml-2 text-xs font-medium text-gray-700 cursor-pointer"
                      >
                        Keep me signed in for this session
                      </label>
                    </div>
                  ) : (
                    <div className="flex items-start mb-6">
                      <input
                        id="agreeTerms"
                        type="checkbox"
                        required
                        checked={formData.agreeTerms}
                        onChange={(e) =>
                          setFormData({
                            ...formData,
                            agreeTerms: e.target.checked,
                          })
                        }
                        className="w-4 h-4 mt-0.5 text-orange-900 border-gray-300 rounded focus:ring-orange-900 cursor-pointer"
                      />
                      <label
                        htmlFor="agreeTerms"
                        className="ml-2.5 text-xs text-gray-600 leading-relaxed cursor-pointer"
                      >
                        I accept the{" "}
                        <a
                          href="#"
                          className="font-semibold text-orange-900 hover:underline"
                        >
                          Terms of Service
                        </a>{" "}
                        and{" "}
                        <a
                          href="#"
                          className="font-semibold text-orange-900 hover:underline"
                        >
                          Privacy Policy
                        </a>
                        .
                      </label>
                    </div>
                  )}

                  {/* Submit Button */}
                  <button
                    type="submit"
                    disabled={isSubmitting}
                    className="relative group block w-full mb-6 py-3.5 px-5 text-center text-sm font-semibold text-white bg-orange-900 rounded-xl overflow-hidden shadow-lg hover:shadow-orange-900/20 transition-all cursor-pointer"
                  >
                    <div className="absolute inset-0 w-full h-full bg-gray-900 -translate-x-full group-hover:translate-x-0 transition-transform duration-300 ease-out" />
                    <span className="relative z-10">
                      {isSubmitting
                        ? "Please wait..."
                        : isSignUp
                          ? "Create Account"
                          : "Login"}
                    </span>
                  </button>

                  {/* Mode Toggle Footer Button */}
                  <div className="text-center text-xs font-semibold text-gray-600">
                    <span>
                      {isSignUp
                        ? "Already have an account?"
                        : "Don’t have an account?"}
                    </span>
                    <button
                      type="button"
                      onClick={() => setIsSignUp(!isSignUp)}
                      className="ml-1 text-orange-900 hover:text-orange-700 hover:underline font-bold cursor-pointer"
                    >
                      {isSignUp ? "Sign In" : "Sign Up"}
                    </button>
                  </div>
                </form>
              </div>
            </div>

          </div>
        </div>
      </div>

      {/* "Coming Soon" Modal Popup */}
      {comingSoonProvider && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          {/* Backdrop Blur */}
          <div
            className="fixed inset-0 bg-gray-900/50 backdrop-blur-sm transition-opacity"
            onClick={() => setComingSoonProvider(null)}
          />

          {/* Modal Content */}
          <div className="relative bg-white rounded-3xl max-w-sm w-full p-8 shadow-2xl border border-gray-100 z-10 text-center transform transition-all animate-in fade-in zoom-in-95 duration-200">
            {/* Close Button */}
            <button
              type="button"
              onClick={() => setComingSoonProvider(null)}
              className="absolute top-4 right-4 p-2 text-gray-400 hover:text-gray-700 rounded-full hover:bg-gray-100 transition-colors"
              aria-label="Close modal"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>

            {/* Icon Badge */}
            <div className="w-14 h-14 mx-auto mb-4 bg-orange-50 border border-orange-100 rounded-2xl flex items-center justify-center text-orange-900 shadow-sm">
              <svg className="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>

            {/* Text Content */}
            <h4 className="text-xl font-bold text-gray-900 mb-2">
              Coming Soon!
            </h4>
            <p className="text-sm text-gray-500 mb-6 leading-relaxed">
              <span className="font-semibold text-gray-800">{comingSoonProvider}</span> authentication is currently in development and will be available in the next release.
            </p>

            {/* Action Button */}
            <button
              type="button"
              onClick={() => setComingSoonProvider(null)}
              className="w-full py-3 px-4 text-sm font-semibold text-white bg-orange-900 hover:bg-orange-800 rounded-xl transition-colors shadow-md hover:shadow-orange-900/20 cursor-pointer"
            >
              Got it, thanks!
            </button>
          </div>
        </div>
      )}
    </section>
  );
}