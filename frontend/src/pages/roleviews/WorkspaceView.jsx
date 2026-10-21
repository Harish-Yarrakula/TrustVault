import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import logo from "../../assets/logo.png";
import avatar from "../../assets/Profile_avatar_placeholder_large.png";

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

export const RoleViewLayout = ({ items = workspaceItems, role = "workspace" }) => {
  const [selectedItem, setSelectedItem] = useState(items[0]);
  const [searchTerm, setSearchTerm] = useState("");
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [filters, setFilters] = useState({
    name: "",
    owner: "",
    category: "",
    date: "",
  });
  const [appliedFilters, setAppliedFilters] = useState({});
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);

  const visibleItems = useMemo(() => {
    const normalizedSearch = searchTerm.trim().toLowerCase();
    if (!normalizedSearch) return items;
    return items.filter((item) =>
      item.label.toLowerCase().includes(normalizedSearch),
    );
  }, [items, searchTerm]);

  const displayedItems = visibleItems;

  const selectItem = (item) => {
    setSelectedItem(item);
    setNotificationsOpen(false);
    setFiltersOpen(false);
    setProfileOpen(false);
  };

  const updateFilter = (event) => {
    const { name, value } = event.target;
    setFilters((currentFilters) => ({ ...currentFilters, [name]: value }));
  };

  const applyFilters = (event) => {
    event.preventDefault();
    setAppliedFilters(
      Object.fromEntries(
        Object.entries(filters).filter(([, value]) => value.trim() !== ""),
      ),
    );
  };

  const clearFilters = () => {
    setFilters({ name: "", owner: "", category: "", date: "" });
    setAppliedFilters({});
  };

  return (
    <section className="relative min-h-screen overflow-hidden bg-white font-sans">
      <div className="flex min-h-screen w-full">
        <aside className="flex w-1/5 min-w-56 flex-col justify-between bg-[#171440] p-5 text-white">
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
            {displayedItems.map((item) => (
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
            {displayedItems.length === 0 && (
              <span className="text-sm text-white/60">No matching options</span>
            )}
          </nav>
          <Link to="/" className="transition-opacity hover:opacity-80">
            LogOut
          </Link>
        </aside>

        <main className="w-4/5">
          <div className="flex items-center justify-between border-b border-gray-200">
            <section className="m-2 flex items-center">
              <input
                type="search"
                name="Search"
                id={`${role}-search`}
                value={searchTerm}
                onChange={(event) => setSearchTerm(event.target.value)}
                className="m-2 rounded-full border border-gray-300 pl-5"
                placeholder="Search"
                aria-label="Search menu options"
              />
              <div className="inline-flex items-center gap-4 rounded-xl p-3">
                <button
                  type="button"
                  onClick={() => setSearchTerm(searchTerm.trim())}
                  className="inline-flex cursor-pointer items-center justify-center rounded-full bg-[#171440] p-2 transition-opacity hover:opacity-80"
                  aria-label="Search"
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
                    <circle cx="11" cy="11" r="8" />
                    <line x1="21" y1="21" x2="16.65" y2="16.65" />
                  </svg>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setFiltersOpen((open) => !open);
                    setNotificationsOpen(false);
                    setProfileOpen(false);
                  }}
                  className={`inline-flex cursor-pointer items-center justify-center rounded-full bg-[#171440] p-2 transition-opacity hover:opacity-80 ${
                    filtersOpen || Object.keys(appliedFilters).length > 0
                      ? "ring-2 ring-orange-400"
                      : ""
                  }`}
                  aria-label="Filter"
                  aria-pressed={filtersOpen}
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
                    <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3" />
                  </svg>
                </button>
              </div>
            </section>
            <section className="m-1 flex items-center">
              <button
                type="button"
                onClick={() => setNotificationsOpen((open) => !open)}
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
                  setFiltersOpen(false);
                }}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    setProfileOpen((open) => !open);
                    setNotificationsOpen(false);
                    setFiltersOpen(false);
                  }
                }}
                aria-label="Open profile menu"
              />
            </section>
          </div>
          {notificationsOpen && (
            <div className="absolute right-5 top-16 z-10 rounded-lg border border-gray-200 bg-white p-4 text-sm text-gray-700 shadow-lg">
              You are all caught up.
            </div>
          )}
          {profileOpen && (
            <div className="absolute right-5 top-16 z-20 w-64 rounded-xl border border-gray-200 bg-white p-4 text-gray-700 shadow-lg">
              <div className="flex items-center gap-3 border-b border-gray-100 pb-3">
                <img src={avatar} alt="" className="size-12 rounded-full" />
                <div>
                  <p className="font-semibold">TrustVault User</p>
                  <p className="text-xs text-gray-500">
                    {role === "admin" ? "Administrator" : "Workspace member"}
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
                <Link
                  to="/"
                  className="block rounded-lg px-2 py-2 hover:bg-gray-100"
                >
                  Log out
                </Link>
              </div>
            </div>
          )}
          <div className="p-3">
            <h1 className="text-3xl font-bold">{selectedItem.label}</h1>
            {filtersOpen ? (
              <form
                onSubmit={applyFilters}
                className="mt-6 rounded-xl border border-gray-200 bg-gray-50 p-6"
              >
                <div className="mb-6">
                  <h2 className="text-xl font-semibold text-gray-900">
                    Filter documents
                  </h2>
                  <p className="mt-1 text-sm text-gray-500">
                    Narrow your document results by name, owner, category, or
                    date.
                  </p>
                </div>
                <div className="grid gap-4 md:grid-cols-2">
                  <label className="text-sm font-medium text-gray-700">
                    Document name
                    <input
                      type="text"
                      name="name"
                      value={filters.name}
                      onChange={updateFilter}
                      placeholder="Search by name"
                      className="mt-2 w-full rounded-lg border border-gray-300 bg-white px-3 py-2 font-normal outline-none focus:border-[#171440] focus:ring-1 focus:ring-[#171440]"
                    />
                  </label>
                  <label className="text-sm font-medium text-gray-700">
                    Owner
                    <input
                      type="text"
                      name="owner"
                      value={filters.owner}
                      onChange={updateFilter}
                      placeholder="Search by owner"
                      className="mt-2 w-full rounded-lg border border-gray-300 bg-white px-3 py-2 font-normal outline-none focus:border-[#171440] focus:ring-1 focus:ring-[#171440]"
                    />
                  </label>
                  <label className="text-sm font-medium text-gray-700">
                    Category
                    <select
                      name="category"
                      value={filters.category}
                      onChange={updateFilter}
                      className="mt-2 w-full rounded-lg border border-gray-300 bg-white px-3 py-2 font-normal outline-none focus:border-[#171440] focus:ring-1 focus:ring-[#171440]"
                    >
                      <option value="">All categories</option>
                      <option value="Contracts">Contracts</option>
                      <option value="Finance">Finance</option>
                      <option value="Reports">Reports</option>
                      <option value="Policies">Policies</option>
                    </select>
                  </label>
                  <label className="text-sm font-medium text-gray-700">
                    Date
                    <input
                      type="date"
                      name="date"
                      value={filters.date}
                      onChange={updateFilter}
                      className="mt-2 w-full rounded-lg border border-gray-300 bg-white px-3 py-2 font-normal outline-none focus:border-[#171440] focus:ring-1 focus:ring-[#171440]"
                    />
                  </label>
                </div>
                <div className="mt-6 flex flex-wrap gap-3">
                  <button
                    type="submit"
                    className="rounded-lg bg-[#171440] px-5 py-2 text-sm font-semibold text-white hover:opacity-90"
                  >
                    Apply filters
                  </button>
                  <button
                    type="button"
                    onClick={clearFilters}
                    className="rounded-lg border border-gray-300 bg-white px-5 py-2 text-sm font-semibold text-gray-700 hover:bg-gray-100"
                  >
                    Clear all
                  </button>
                </div>
                {Object.keys(appliedFilters).length > 0 && (
                  <p className="mt-4 text-sm text-gray-600">
                    {Object.keys(appliedFilters).length} filter
                    {Object.keys(appliedFilters).length === 1 ? "" : "s"}{" "}
                    applied.
                  </p>
                )}
              </form>
            ) : (
              <div className="mt-6 min-h-64 rounded-xl border border-dashed border-gray-300 p-8 text-center text-gray-600">
                {selectedItem.description}
              </div>
            )}
          </div>
        </main>
      </div>
    </section>
  );
};

const WorkspaceView = () => (
  <RoleViewLayout items={workspaceItems} role="workspace" />
);

export default WorkspaceView;
