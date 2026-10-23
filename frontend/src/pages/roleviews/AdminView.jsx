import { RoleViewLayout } from "./WorkspaceView";

const adminItems = [
  {
    label: "Dashboard",
    description: "Monitor workspace health, activity, and security status.",
  },
  {
    label: "Document Logs",
    description: "Review document access, changes, uploads, and sharing events.",
  },
  {
    label: "User & Role Setting",
    description: "Manage users, permissions, and role assignments.",
  },
  {
    label: "Settings",
    description: "Manage administrative and workspace-wide settings.",
  },
];

const AdminView = ({ user }) => (
  <RoleViewLayout items={adminItems} role="admin" user={user} />
);

export default AdminView;
