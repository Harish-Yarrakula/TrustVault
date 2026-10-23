const sensitiveCategories = new Set(["Finance", "Contracts", "Policies"]);

export function evaluateAccessRules(document, user) {
  if (!document) return [];

  const findings = [];
  const category = String(document.category || "").trim();
  const name = String(document.name || "").toLowerCase();
  const isSensitive = sensitiveCategories.has(category) ||
    /(confidential|secret|private|payroll|tax|legal|security)/i.test(name);

  if (isSensitive) {
    findings.push({
      id: "sensitive-document",
      severity: "high",
      title: "Sensitive document",
      detail: "Use the minimum required permission and require human confirmation before granting access.",
    });
  }

  if (!document.owner_id) {
    findings.push({
      id: "missing-owner",
      severity: "high",
      title: "Owner could not be verified",
      detail: "Do not grant access until the document owner is available from the server.",
    });
  }

  if (user?.account_type === "EXTERNAL_CLIENT" || user?.role === "EXTERNAL_CLIENT") {
    findings.push({
      id: "external-review",
      severity: "high",
      title: "External account",
      detail: "External accounts must not approve access suggestions or broaden document permissions.",
    });
  }

  if (!document.content_sha256) {
    findings.push({
      id: "integrity-metadata",
      severity: "medium",
      title: "Integrity metadata is missing",
      detail: "Verify the document checksum before sharing it outside the workspace.",
    });
  }

  if (!findings.length) {
    findings.push({
      id: "baseline-review",
      severity: "low",
      title: "Baseline review",
      detail: "No additional metadata risk was detected. Human approval is still required.",
    });
  }

  return findings;
}
