import { useState } from "react";

const allowedTypes = ["application/pdf", "image/png", "image/jpeg"];
const maxFileSize = 10 * 1024 * 1024;

const UploadPanel = ({ onUpload }) => {
  const [file, setFile] = useState(null);
  const [category, setCategory] = useState("");
  const [permissionEmails, setPermissionEmails] = useState("");
  const [permissionLevel, setPermissionLevel] = useState("READ");
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  const validateFile = (selectedFile) => {
    if (!allowedTypes.includes(selectedFile.type)) {
      return "Only PDF, PNG, and JPEG files are supported.";
    }
    if (selectedFile.size > maxFileSize) {
      return "The file must be smaller than 10 MB.";
    }
    return "";
  };

  const handleFileChange = (event) => {
    const selectedFile = event.target.files?.[0];
    setMessage("");
    if (!selectedFile) {
      setFile(null);
      return;
    }
    const validationError = validateFile(selectedFile);
    setError(validationError);
    setFile(validationError ? null : selectedFile);
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (!file || !category) {
      setError("Choose a valid file and category before uploading.");
      return;
    }
    try {
      const emails = [...new Set(permissionEmails.split(/[,\s;]+/).map((email) => email.trim().toLowerCase()).filter(Boolean))];
      const invalidEmail = emails.find((email) => !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email));
      if (invalidEmail) {
        setError(`Enter a valid email address: ${invalidEmail}`);
        return;
      }
      await onUpload?.({ file, category, permissionEmails: emails, permissionLevel });
      setError("");
      setMessage(`${file.name} uploaded successfully.`);
      setFile(null);
      setCategory("");
      setPermissionEmails("");
      setPermissionLevel("READ");
      event.target.reset();
    } catch (uploadError) {
      setError(uploadError.message || "The upload failed.");
      setMessage("");
    }
  };

  return (
    <form
      onSubmit={handleSubmit}
      className="mt-6 max-w-2xl rounded-xl border border-gray-200 bg-white p-6"
    >
      <h2 className="text-xl font-semibold text-gray-900">Upload a document</h2>
      <p className="mt-1 text-sm text-gray-500">
        PDF, PNG, and JPEG files up to 10 MB are accepted.
      </p>
      <div className="mt-5 grid gap-4 sm:grid-cols-2">
        <label className="text-sm font-medium text-gray-700 sm:col-span-2">
          File
          <input
            type="file"
            accept=".pdf,.png,.jpg,.jpeg"
            onChange={handleFileChange}
            className="mt-2 block w-full rounded-lg border border-gray-300 bg-white p-2 text-sm"
          />
        </label>
        <label className="text-sm font-medium text-gray-700">
          Category
          <select
            value={category}
            onChange={(event) => setCategory(event.target.value)}
            className="mt-2 w-full rounded-lg border border-gray-300 bg-white px-3 py-2 font-normal"
          >
            <option value="">Choose category</option>
            <option value="Contracts">Contracts</option>
            <option value="Finance">Finance</option>
            <option value="Reports">Reports</option>
            <option value="Policies">Policies</option>
          </select>
        </label>
        <label className="text-sm font-medium text-gray-700 sm:col-span-2">
          Grant access by email
          <textarea
            value={permissionEmails}
            onChange={(event) => setPermissionEmails(event.target.value)}
            placeholder="person1@example.com, person2@example.com"
            className="mt-2 min-h-20 w-full rounded-lg border border-gray-300 bg-white px-3 py-2 font-normal"
            aria-label="Emails to grant document access"
          />
          <span className="mt-1 block text-xs font-normal text-gray-500">Registered members receive access immediately; other addresses receive an invitation.</span>
        </label>
        <label className="text-sm font-medium text-gray-700">
          Permission
          <select value={permissionLevel} onChange={(event) => setPermissionLevel(event.target.value)} className="mt-2 w-full rounded-lg border border-gray-300 bg-white px-3 py-2 font-normal">
            <option value="READ">Read</option>
            <option value="WRITE">Write</option>
          </select>
        </label>
      </div>
      {error && <p className="mt-4 text-sm text-red-600">{error}</p>}
      {message && <p className="mt-4 text-sm text-green-700">{message}</p>}
      <button
        type="submit"
        className="mt-5 rounded-lg bg-[#171440] px-5 py-2 text-sm font-semibold text-white hover:opacity-90"
      >
        Validate and upload
      </button>
    </form>
  );
};

export default UploadPanel;
