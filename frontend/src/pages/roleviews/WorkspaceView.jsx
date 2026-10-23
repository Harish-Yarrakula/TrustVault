import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import logo from "../../assets/logo.png";
import avatar from "../../assets/Profile_avatar_placeholder_large.png";
import AuditLog from "../../components/AuditLog";
import DocumentLibrary from "../../components/DocumentLibrary";
import DocumentDetails from "../../components/DocumentDetails";
import ShareDialog from "../../components/ShareDialog";
import AdminDashboard from "../../components/AdminDashboard";
import RoleSettings from "../../components/RoleSettings";
import SettingsPanel from "../../components/SettingsPanel";
import UploadPanel from "../../components/UploadPanel";
import PermissionManager from "../../components/PermissionManager";
import { api, setAccessToken } from "../../api";
import { evaluateAccessRules } from "../../utils/accessRules";

const workspaceItems = [
  {
    label: "Dashboard",
    description: "Overview of your files, recent activity, and storage.",
  },
  {
    label: "Documents",
    description: "Browse, organize, and manage your secure documents.",
  },
  {
    label: "Shared with me",
    description: "Documents and folders shared with you by your team.",
  },
  {
    label: "Upload files",
    description: "Add new files to your secure TrustVault workspace.",
  },
  {
    label: "Settings",
    description: "Manage your profile, preferences, and workspace settings.",
  },
];

export const RoleViewLayout = ({ items = workspaceItems, role = "workspace", user }) => {
  const [selectedItem, setSelectedItem] = useState(items[0]);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [darkMode, setDarkMode] = useState(() => localStorage.getItem("trustvault_theme") === "dark");
  const [aiOpen, setAiOpen] = useState(false);
  const [aiDocument, setAiDocument] = useState("");
  const [aiSuggestions, setAiSuggestions] = useState([]);
  const [aiError, setAiError] = useState("");
  const [aiBusy, setAiBusy] = useState(false);
  const [documents, setDocuments] = useState([]);
  const [sharedDocuments, setSharedDocuments] = useState([]);
  const [members, setMembers] = useState([]);
  const [selectedDocument, setSelectedDocument] = useState(null);
  const [shareDocument, setShareDocument] = useState(null);
  const [loadError, setLoadError] = useState("");
  const [memberCount, setMemberCount] = useState(null);
  const [hasNewMember, setHasNewMember] = useState(false);
  const [notifications, setNotifications] = useState([]);
  const [uploadedDocument, setUploadedDocument] = useState(null);
  const [seenNotificationIds, setSeenNotificationIds] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem("trustvault_seen_notifications") || "[]");
    } catch {
      return [];
    }
  });
  const securityAlerts = notifications.filter((event) =>
    ["USER_LOGIN_FAILED", "EMAIL_FAILED", "ACCESS_DENIED"].includes(event.action),
  );
  const unseenSecurityAlerts = securityAlerts.filter((event) => !event.read_at && !seenNotificationIds.includes(event.id));
  const securityAlertCount = unseenSecurityAlerts.length;

  const selectItem = (item) => {
    setSelectedItem(item);
    setSelectedDocument(null);
    setNotificationsOpen(false);
    setProfileOpen(false);
    setMobileNavOpen(false);
  };

  const toggleDarkMode = () => {
    setDarkMode((current) => {
      const next = !current;
      localStorage.setItem("trustvault_theme", next ? "dark" : "light");
      return next;
    });
  };

  const markNotificationsSeen = () => {
    const ids = securityAlerts.filter((event) => !event.read_at).map((event) => event.id);
    setSeenNotificationIds(ids);
    localStorage.setItem("trustvault_seen_notifications", JSON.stringify(ids));
    if (ids.length) {
      api.markNotificationsRead(ids).catch((error) => setLoadError(error.message));
    }
    setNotifications((current) => current.map((notification) =>
      ids.includes(notification.id) ? { ...notification, read_at: new Date().toISOString() } : notification,
    ));
    setHasNewMember(false);
  };

  useEffect(() => {
    Promise.all([
      api.documents(),
      api.sharedDocuments(),
      api.members(),
      role === "admin" ? api.notifications() : Promise.resolve([]),
    ])
      .then(([allDocuments, grantedDocuments, companyMembers, notificationRows]) => {
        setDocuments(role === "admin" ? allDocuments : allDocuments.filter((document) => document.owner_id === user?.id));
        setSharedDocuments(grantedDocuments);
        setMembers(companyMembers);
        setNotifications(notificationRows);
      })
      .catch((error) => setLoadError(error.message));
    if (role === "admin") {
      api.members().then((companyMembers) => {
        const previousCount = Number(localStorage.getItem("trustvault_member_count") || 0);
        setMemberCount(companyMembers.length);
        setHasNewMember(previousCount > 0 && companyMembers.length > previousCount);
        localStorage.setItem("trustvault_member_count", String(companyMembers.length));
      }).catch((error) => setLoadError(error.message));
    }
  }, [role, user?.id]);

  const handleUpload = async ({ file, category, permissionEmails = [], permissionLevel = "READ" }) => {
    const document = await api.uploadDocument(file, category);
    try {
      const membersByEmail = new Map(members.map((member) => [member.email.toLowerCase(), member]));
      for (const email of permissionEmails) {
        const member = membersByEmail.get(email);
        if (member) {
          await api.grantPermission(document.id, {
            user_id: member.id,
            permission_level: permissionLevel,
          });
        } else {
          await api.inviteGuest({
            email,
            document_id: document.id,
            permission_level: permissionLevel,
          });
        }
      }
    } catch (error) {
      try {
        await api.deleteDocument(document.id);
      } catch (cleanupError) {
        throw new Error(`Document uploaded, but permission setup failed and cleanup was unsuccessful: ${error.message}`, { cause: cleanupError });
      }
      throw new Error(`Upload cancelled because permission setup failed: ${error.message}`, { cause: error });
    }
    setDocuments((currentDocuments) => [document, ...currentDocuments]);
    setUploadedDocument(document);
  };

  const requestAiSuggestions = async () => {
    if (!aiDocument) return;
    try {
      setAiBusy(true);
      setAiError("");
      setAiSuggestions(await api.accessSuggestions({ document_id: aiDocument }));
    } catch (error) {
      setAiError(error.message);
    } finally {
      setAiBusy(false);
    }
  };

  const decideAiSuggestion = async (suggestion, approve) => {
    try {
      setAiError("");
      const updated = await api.decideAccessSuggestion(suggestion.id, { approve });
      setAiSuggestions((current) => current.filter((item) => item.id !== updated.id));
    } catch (error) {
      setAiError(error.message);
    }
  };

  const handleLogout = async () => {
    try { await api.logout(); } finally {
      setAccessToken(null);
      window.location.href = "/auth/login";
    }
  };

  const renderSelectedContent = () => {
    if (role === "admin" && selectedItem.label === "Document Logs") {
      return <AuditLog />;
    }

    if (role === "admin" && selectedItem.label === "User & Role Setting") {
      return <RoleSettings />;
    }
    if (role === "admin" && selectedItem.label === "Dashboard") {
      return <AdminDashboard />;
    }
    if (selectedItem.label === "Settings") {
      return <SettingsPanel user={user} />;
    }

    if (selectedDocument) {
      const owner = members.find((member) => member.id === selectedDocument.owner_id) ||
        (user?.id === selectedDocument.owner_id ? user : null);
      return (
        <DocumentDetails
          document={selectedDocument}
          owner={owner}
          canManage={user?.id === selectedDocument.owner_id}
          onBack={() => setSelectedDocument(null)}
        />
      );
    }

    if (selectedItem.label === "Documents" || selectedItem.label === "Dashboard") {
      return (
        <DocumentLibrary
          documents={documents}
          error={loadError}
          onDownload={async (document) => {
            const { blob } = await api.downloadContent(document.id);
            const url = URL.createObjectURL(blob);
            window.open(url, "_blank", "noopener,noreferrer");
            setTimeout(() => URL.revokeObjectURL(url), 60_000);
          }}
          onSelect={setSelectedDocument}
          canShare={(document) => document.owner_id === user?.id}
          onShare={(document) => setShareDocument(document)}
          onDelete={async (document) => {
            await api.deleteDocument(document.id);
            setDocuments((current) => current.filter((item) => item.id !== document.id));
          }}
        />
      );
    }

    if (selectedItem.label === "Upload files") {
      return (
        <>
          <UploadPanel onUpload={handleUpload} />
          {uploadedDocument && user?.id === uploadedDocument.owner_id && (
            <PermissionManager document={uploadedDocument} />
          )}
        </>
      );
    }

    if (selectedItem.label === "Shared with me") {
      return (
        <DocumentLibrary
          documents={sharedDocuments}
          onSelect={setSelectedDocument}
          onDownload={async (document) => {
            const { blob } = await api.downloadContent(document.id);
            const url = URL.createObjectURL(blob);
            window.open(url, "_blank", "noopener,noreferrer");
            setTimeout(() => URL.revokeObjectURL(url), 60_000);
          }}
          error={loadError}
        />
      );
    }

    return (
      <div className="mt-6 min-h-64 rounded-xl border border-dashed border-gray-300 p-8 text-center text-gray-600">
        {selectedItem.description}
      </div>
    );
  };

  return (
    <section className={`workspace-shell relative min-h-screen overflow-hidden font-sans ${darkMode ? "dark-mode" : ""}`}>
      <div className="flex min-h-screen w-full">
        <aside className={`workspace-sidebar fixed inset-y-0 left-0 z-30 flex w-72 max-w-[85vw] flex-col justify-between bg-[#171440] p-5 text-white transition-transform lg:static lg:w-[min(22vw,18rem)] lg:max-w-none ${mobileNavOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"}`}>
          <div>
            <Link
              to="/dashboard"
              className="flex items-center space-x-2 text-xl font-bold tracking-tight"
            >
              <img
                src={logo}
                alt="TrustVaultLogo"
                className="flex h-8 w-8 items-center justify-center rounded-lg"
              />
              <span className="text-xl text-white">TrustVault</span>
            </Link>
          </div>
          <nav aria-label={`${role} navigation`} className="flex flex-col gap-5">
            {items.map((item) => (
              <button
                key={item.label}
                type="button"
                onClick={() => selectItem(item)}
                className={`text-left transition-opacity hover:opacity-80 ${
                  selectedItem.label === item.label ? "font-bold" : ""
                }`}
                aria-current={
                  selectedItem.label === item.label ? "page" : undefined
                }
              >
                {item.label}
              </button>
            ))}
          </nav>
          <button type="button" onClick={handleLogout} className="text-left transition-opacity hover:opacity-80">
            LogOut
          </button>
        </aside>

        <main className="min-w-0 flex-1">
          <div className="workspace-header flex items-center justify-between border-b border-gray-200 px-4 py-3 sm:px-8">
            <div className="flex items-center gap-3">
              <button type="button" onClick={() => setMobileNavOpen(true)} className="rounded-lg border border-gray-200 p-2 lg:hidden" aria-label="Open navigation">
                <span className="text-lg">☰</span>
              </button>
              <h1 className="text-2xl font-bold sm:text-3xl">{selectedItem.label}</h1>
            </div>
            <section className="m-1 flex items-center">
              <button type="button" onClick={toggleDarkMode} className="mr-2 rounded-full border border-gray-200 px-3 py-1.5 text-xs font-semibold" aria-label="Toggle dark mode">
                {darkMode ? "Light" : "Dark"}
              </button>
              <button
                type="button"
                onClick={() => {
                  setNotificationsOpen((open) => !open);
                  if (!notificationsOpen) markNotificationsSeen();
                }}
                className="inline-flex size-7 cursor-pointer items-center justify-center rounded-full bg-[#171440] p-2 transition-opacity hover:opacity-80"
                aria-label="Notifications"
                aria-expanded={notificationsOpen}
              >
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  width={10}
                  height={10}
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="#FFFFFF"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
                  <path d="M13.73 21a2 2 0 0 1-3.46 0" />
                </svg>
                {(role === "admin" && hasNewMember || securityAlertCount > 0) && (
                  <span className="absolute ml-3 mt-[-18px] size-2 rounded-full bg-red-500" />
                )}
              </button>
              <img
                src={avatar}
                alt="profile"
                className="m-3 size-10 cursor-pointer rounded-full"
                role="button"
                tabIndex={0}
                onClick={() => {
                  setProfileOpen((open) => !open);
                  setNotificationsOpen(false);
                }}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    setProfileOpen((open) => !open);
                    setNotificationsOpen(false);
                  }
                }}
                aria-label="Open profile menu"
              />
            </section>
          </div>
          {notificationsOpen && (
            <div className="panel absolute right-5 top-16 z-10 rounded-lg border border-gray-200 p-4 text-sm shadow-lg">
              {securityAlertCount > 0
                ? `${securityAlertCount} new security alert(s) need review.`
                : role === "admin" && hasNewMember
                  ? `A new company member joined your workspace. ${memberCount} total members.`
                  : "You are all caught up."}
            </div>
          )}
          {profileOpen && (
            <div className="panel absolute right-5 top-16 z-20 w-64 rounded-xl border border-gray-200 p-4 text-gray-700 shadow-lg">
              <div className="flex items-center gap-3 border-b border-gray-100 pb-3">
                <img src={avatar} alt="" className="size-12 rounded-full" />
                <div>
                  <p className="font-semibold">{user?.full_name || user?.email || "TrustVault User"}</p>
                  <p className="text-xs text-gray-500">{user?.email}</p>
                  <p className="text-xs text-gray-500">
                    {role === "admin" ? "Administrator" : user?.role === "EXTERNAL_CLIENT" ? "External client" : "Member"}
                  </p>
                </div>
              </div>
              <div className="mt-3 space-y-2 text-sm">
                <button
                  type="button"
                  onClick={() => {
                    const settingsItem = items.find(
                      (item) => item.label === "Settings",
                    );
                    if (settingsItem) selectItem(settingsItem);
                  }}
                  className="block w-full rounded-lg px-2 py-2 text-left hover:bg-gray-100"
                >
                  Profile settings
                </button>
                <button
                  type="button"
                  onClick={handleLogout}
                  className="block w-full rounded-lg px-2 py-2 text-left hover:bg-gray-100"
                >
                  Log out
                </button>
              </div>
            </div>
          )}
          <div className="workspace-content mx-auto w-full max-w-[1600px] p-3 sm:p-6">{renderSelectedContent()}</div>
        </main>
      </div>
      {mobileNavOpen && <button type="button" className="fixed inset-0 z-20 bg-black/40 lg:hidden" onClick={() => setMobileNavOpen(false)} aria-label="Close navigation" />}
      <button type="button" onClick={() => setAiOpen((open) => !open)} className="ai-fab fixed bottom-5 right-5 z-40 flex size-14 items-center justify-center rounded-full bg-[#f97316] text-lg font-black text-white shadow-xl transition-transform hover:scale-105" aria-label="Open AI assistant">AI</button>
      {aiOpen && (
        <aside className="panel fixed bottom-24 right-5 z-40 w-[min(24rem,calc(100vw-2rem))] rounded-2xl border border-gray-200 p-5 shadow-2xl">
          <div className="flex items-start justify-between gap-3">
            <div><h2 className="text-lg font-bold">AI access assistant</h2><p className="mt-1 text-xs text-gray-500">Review least-privilege access suggestions.</p></div>
            <button type="button" onClick={() => setAiOpen(false)} aria-label="Close AI assistant">×</button>
          </div>
          <select value={aiDocument} onChange={(event) => setAiDocument(event.target.value)} className="mt-4 w-full rounded-lg border border-gray-300 px-3 py-2 text-sm">
            <option value="">Choose a document</option>
            {documents.map((document) => <option key={document.id} value={document.id}>{document.name}</option>)}
          </select>
          <button type="button" onClick={requestAiSuggestions} disabled={!aiDocument || aiBusy} className="mt-3 w-full rounded-lg bg-[#171440] px-3 py-2 text-sm font-semibold text-white disabled:opacity-50">{aiBusy ? "Analyzing..." : "Get AI suggestions"}</button>
          {aiError && <p role="alert" className="mt-3 text-xs text-red-600">{aiError}</p>}
          {aiDocument && (
            <div className="mt-4 rounded-lg border border-orange-200 bg-orange-50 p-3 text-xs text-gray-800">
              <p className="font-semibold">Rule-based safety checks</p>
              <ul className="mt-2 space-y-2">
                {evaluateAccessRules(documents.find((document) => document.id === aiDocument), user).map((finding) => (
                  <li key={finding.id}><strong>{finding.severity.toUpperCase()}: {finding.title}.</strong> {finding.detail}</li>
                ))}
              </ul>
            </div>
          )}
          <div className="mt-3 space-y-2">
            {aiSuggestions.map((suggestion) => <div key={suggestion.id} className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-xs"><p className="font-semibold">{suggestion.suggested_email} · {suggestion.permission_level}</p><p className="mt-1">{suggestion.rationale}</p><div className="mt-2 flex gap-2"><button type="button" onClick={() => decideAiSuggestion(suggestion, true)} className="rounded bg-green-700 px-2 py-1 text-white">Confirm</button><button type="button" onClick={() => decideAiSuggestion(suggestion, false)} className="rounded border border-gray-300 px-2 py-1">Reject</button></div></div>)}
            {!aiBusy && aiDocument && !aiSuggestions.length && !aiError && <p className="text-xs text-gray-500">No pending suggestions for this document.</p>}
          </div>
        </aside>
      )}
      {shareDocument && (
        <ShareDialog document={shareDocument} onClose={() => setShareDocument(null)} />
      )}
    </section>
  );
};

const WorkspaceView = ({ user }) => (
  <RoleViewLayout items={workspaceItems} role="workspace" user={user} />
);

export default WorkspaceView;
