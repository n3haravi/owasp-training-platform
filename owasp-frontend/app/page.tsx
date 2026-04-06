"use client";

import { useMemo, useState } from "react";

interface Vulnerability {
  key: string;
  message: string;
  severity: string;
  project: string;
  owasp: string;
  source: string;
}

interface Top5Item {
  owasp: string;
  count: number;
  training: string;
}

type GroupedResponse = Record<string, Vulnerability[]>;
type Top5Response = Record<string, Top5Item[]>;


const PROJECT_LABELS: Record<string, string> = {
  webgoat: "WebGoat",
  "juice-shop": "Juice Shop",
};


interface GuidanceData {
  guidance: string;
  mitigations: string[];
}

// Simple guidance + mitigation content per OWASP category
const OWASP_GUIDANCE: Record<string, GuidanceData> = {
  "A01: Broken Access Control": {
    guidance:
      "Ensure that every request is authorized on the server side, not just in the UI. Focus on object-level access control and avoiding IDOR issues in this application.",
    mitigations: [
      "Add explicit authorization checks for every endpoint and resource (e.g., verify the current user owns the object they are accessing).",
      "Use a central authorization layer or policy engine rather than scattered ad‑hoc checks.",
      "Add regression tests for IDOR and privilege escalation scenarios per application (e.g., between WebGoat users or Juice Shop customers).",
    ],
  },
  "A02: Cryptographic Failures": {
    guidance:
      "Use strong, modern cryptographic primitives and never store secrets or passwords in plain text. In each application, review where data is encrypted or hashed.",
    mitigations: [
      "Use well‑reviewed crypto libraries (no custom crypto) and modern TLS (1.2+).",
      "Hash passwords with Argon2 or bcrypt with per‑user salts; never log or transmit passwords in cleartext.",
      "Store secrets in a secure vault and rotate keys regularly; avoid embedding secrets in code or configs.",
    ],
  },
  "A03: Injection": {
    guidance:
      "Avoid building queries or commands via string concatenation. In this application, focus on all DB queries, search filters, and any external command execution.",
    mitigations: [
      "Use parameterized queries / prepared statements or ORM query builders for all data access.",
      "Validate and sanitize untrusted input with allowlists and strict typing (numbers, enums).",
      "Remove or refactor any dynamic command execution (e.g., shell, eval, dynamic SQL) and add tests for typical injection payloads.",
    ],
  },
  "A04: Insecure Design": {
    guidance:
      "Treat security as a design requirement, not just an implementation detail. For each application, think in terms of misuse/abuse cases.",
    mitigations: [
      "Perform lightweight threat modeling for sensitive features (auth, payments, admin flows).",
      "Introduce rate‑limits, captcha, and workflow constraints where abuse is likely.",
      "Centralize critical security decisions (authZ, input validation) instead of duplicating them.",
    ],
  },
  "A05: Security Misconfiguration": {
    guidance:
      "Make sure each environment is hardened and consistent. Avoid debug settings, verbose errors, and default accounts in WebGoat/Juice Shop deployments.",
    mitigations: [
      "Disable debug / verbose error pages in production and return generic error messages.",
      "Remove default accounts, sample apps, and unused services or admin consoles.",
      "Manage configuration as code; add checks in CI to assert secure settings (CORS, headers, TLS, etc.).",
    ],
  },
  "A06: Vulnerable & Outdated Components": {
    guidance:
      "Keep libraries, frameworks, and containers up to date for each application and remove anything you no longer need.",
    mitigations: [
      "Maintain an SBOM and use SCA tooling in CI to detect vulnerable dependencies.",
      "Pin versions and patch quickly when security advisories are published.",
      "Remove unused dependencies and transitive baggage from both WebGoat and Juice Shop services.",
    ],
  },
  "A07: Identification & Authentication Failures": {
    guidance:
      "Use proven authentication mechanisms and protect sessions correctly. Check login, password reset, and token usage patterns per application.",
    mitigations: [
      "Use standard auth protocols (OIDC/SAML) and libraries instead of custom auth implementations.",
      "Protect sessions with Secure/HttpOnly/SameSite cookies and rotate tokens on login and privilege changes.",
      "Add MFA where appropriate and rate‑limit login and password reset attempts.",
    ],
  },
  "A08: Software & Data Integrity Failures": {
    guidance:
      "Protect your build and deployment pipeline and verify integrity of artifacts. For each app, ensure untrusted data cannot alter code or configuration.",
    mitigations: [
      "Sign build artifacts and verify signatures before deployment.",
      "Lock down CI/CD with least privilege, protected branches, and secured secrets.",
      "Avoid insecure deserialization of untrusted data and validate all serialized payloads.",
    ],
  },
  "A09: Security Logging & Monitoring Failures": {
    guidance:
      "Log important security events for each application and make sure alerts exist for suspicious patterns.",
    mitigations: [
      "Log authentication events, permission changes, admin actions, and data exports with user and context.",
      "Centralize logs (e.g., ELK/SIEM) and protect them from tampering or direct public access.",
      "Define alerts for repeated login failures, anomalous access patterns, and unexpected errors, and rehearse incident response.",
    ],
  },
  "A10: Server-Side Request Forgery": {
    guidance:
      "Limit or avoid server‑side HTTP requests that depend on user‑controlled input. Review any HTTP client code in these apps.",
    mitigations: [
      "Avoid directly using user‑provided URLs in server‑side HTTP clients; enforce strict allowlists where external calls are required.",
      "Block access to internal IP ranges and metadata endpoints via network and application‑level controls.",
      "Set conservative timeouts, limit redirects, and log all outbound requests made on behalf of users.",
    ],
  },
};

function severityBadge(sev?: string) {
  const s = (sev || "").toLowerCase();

  if (s.includes("critical")) return "bg-red-700 text-white";
  if (s.includes("high")) return "bg-red-600 text-white";
  if (s.includes("medium")) return "bg-amber-500 text-white";
  if (s.includes("low")) return "bg-green-600 text-white";

  return "bg-gray-600 text-white";
}

export default function Dashboard() {
  const [files, setFiles] = useState<FileList | null>(null);
  const [data, setData] = useState<GroupedResponse>({});
  const [top5, setTop5] = useState<Top5Response | null>(null);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // Filter for vulnerability tables
  const [projectFilter, setProjectFilter] = useState("all");

  // Selected vulnerability for “next page” detail view
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);

  // Detect projects from Top5 response
  const projectsInResponse = useMemo(() => {
    const keys = top5 ? Object.keys(top5) : [];

    const known = ["webgoat", "juice-shop"].filter((k) => keys.includes(k));

    const other = keys
      .filter((k) => !known.includes(k))
      .sort();

    return [...known, ...other];
  }, [top5]);

  const [top5Tab, setTop5Tab] = useState<string>("webgoat");

  const analyze = async () => {
    if (!files) {
      setError("Please upload JSON files first.");
      return;
    }

    setLoading(true);
    setError("");
    setData({});
    setTop5(null);


    const formData = new FormData();
    Array.from(files).forEach((f) => formData.append("files", f));

    try {
      const res = await fetch("http://localhost:8000/upload", {
        method: "POST",
        body: formData,
      });

      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }

      const json = await res.json();

      setData((json.grouped || {}) as GroupedResponse);
      setTop5((json.top5 || {}) as Top5Response);


      const keys = Object.keys((json.top5 || {}) as Top5Response);

      if (keys.length > 0) {
        const preferred = keys.includes("webgoat") ? "webgoat" : keys[0];
        setTop5Tab(preferred);
      }
    } catch {
      setError("Failed to analyze vulnerabilities.");
    }

    setLoading(false);
  };

  // ---------------- DETAIL “PAGE” FOR ONE VULNERABILITY ----------------

  if (selectedVuln) {
    const niceProject = PROJECT_LABELS[selectedVuln.project] ?? selectedVuln.project;

    const guidance =
      OWASP_GUIDANCE[selectedVuln.owasp] || {
        guidance:
          "Follow OWASP Top 10 secure coding practices for this category in this application.",
        mitigations: [
          "Review how this feature handles untrusted input and sensitive operations.",
          "Apply least privilege, defense in depth, and secure defaults for this code path.",
          "Add regression tests for the specific vulnerability to prevent reintroduction.",
        ],
      };

    return (
      <div className="min-h-screen bg-gray-50">
        <div className="mx-auto max-w-4xl p-6">
          <button
            onClick={() => setSelectedVuln(null)}
            className="mb-4 inline-flex items-center text-sm text-blue-700 hover:underline"
          >
            ← Back to dashboard
          </button>

          <h1 className="mb-2 text-2xl font-bold tracking-tight">
            Vulnerability guidance & mitigation
          </h1>
          <p className="mb-6 text-gray-600">
            Detailed secure programming guidance for this finding in{" "}
            <span className="font-semibold">{niceProject}</span>.
          </p>

          {/* Summary card */}
          <div className="mb-6 rounded-xl border bg-white p-4 shadow-sm">
            <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
              <div className="space-y-1">
                <div className="text-sm text-gray-500">Key</div>
                <div className="font-mono text-sm">{selectedVuln.key}</div>
                <div className="mt-3 text-sm text-gray-500">Application</div>
                <div className="text-sm font-medium">{niceProject}</div>
              </div>

              <div className="space-y-1">
                <div className="text-sm text-gray-500">OWASP Category</div>
                <div className="text-sm font-semibold">{selectedVuln.owasp}</div>
                <div className="mt-3 text-sm text-gray-500">Severity</div>
                <span
                  className={[
                    "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium",
                    severityBadge(selectedVuln.severity),
                  ].join(" ")}
                >
                  {selectedVuln.severity}
                </span>
              </div>

              <div className="space-y-1">
                <div className="text-sm text-gray-500">Classification source</div>
                <div className="text-sm text-gray-700">{selectedVuln.source}</div>
              </div>
            </div>

            <div className="mt-4">
              <div className="mb-1 text-sm text-gray-500">Scanner message</div>
              <div className="rounded-md bg-gray-50 p-3 text-sm text-gray-800">
                {selectedVuln.message}
              </div>
            </div>
          </div>

          {/* Guidance */}
          <div className="mb-6 rounded-xl border bg-white p-4 shadow-sm">
            <h2 className="mb-2 text-lg font-semibold">Secure programming guidance</h2>
            <p className="text-sm leading-relaxed text-gray-800">
              {guidance.guidance}
            </p>
            <p className="mt-3 text-sm leading-relaxed text-gray-700">
              In{" "}
              <span className="font-medium">
                {niceProject}
              </span>
              , focus these practices on its specific tech stack, frameworks, and
              deployment model to address this vulnerability effectively.
            </p>
          </div>

          {/* Mitigations */}
          <div className="rounded-xl border bg-white p-4 shadow-sm">
            <h2 className="mb-2 text-lg font-semibold">Recommended mitigation steps</h2>
            <p className="mb-2 text-sm text-gray-600">
              Prioritize changes in the context of{" "}
              <span className="font-medium">{niceProject}</span> (its architecture,
              integrations, and hosting environment).
            </p>
            <ul className="list-disc space-y-1 pl-5 text-sm text-gray-800">
              {guidance.mitigations.map((m, idx) => (
                <li key={idx}>{m}</li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    );
  }

  // ---------------- MAIN DASHBOARD VIEW ----------------

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="mx-auto max-w-6xl p-6">
        {/* Header */}
        <div className="mb-6">
          <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
            <div>
              <h1 className="text-3xl font-bold tracking-tight">
                OWASP Vulnerabilities Dashboard
              </h1>
              <p className="mt-1 text-gray-600">
                Upload SAST JSON reports, get OWASP grouping, Top 5 per app, and secure
                programming training guidance for each Top 5 item. Click any vulnerability
                row to open per-application guidance and mitigation on the next page.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <a
                href="/auth"
                className="rounded-md bg-slate-900 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-slate-800 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900"
              >
                Sign In to Portal
              </a>
            </div>
          </div>
        </div>

        {/* Upload Section */}
        <div className="mb-6 rounded-xl border bg-white p-4 shadow-sm">
          <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
            <div className="flex flex-col gap-2">
              <label className="font-medium">Upload JSON reports</label>

              <input
                type="file"
                multiple
                accept=".json"
                onChange={(e) => setFiles(e.target.files)}
                className="block w-full rounded-md border p-2"
              />

              <p className="text-sm text-gray-500">
                Tip: include “webgoat” or “juice” in filenames to auto-tag projects.
              </p>
            </div>

            <div className="flex items-center gap-3">
              <button
                onClick={analyze}
                disabled={loading}
                className="rounded-md bg-blue-600 px-4 py-2 font-medium text-white hover:bg-blue-700 disabled:opacity-60"
              >
                {loading ? "Analyzing…" : "Analyze Vulnerabilities"}
              </button>
            </div>
          </div>

          {error && (
            <div className="mt-4 rounded-md border border-red-200 bg-red-50 p-3 text-red-700">
              {error}
            </div>
          )}
        </div>

        {/* Top 5 Section */}
        {top5 && projectsInResponse.length > 0 && (
          <div className="mb-8 rounded-xl border bg-white p-4 shadow-sm">
            <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
              <div>
                <h2 className="text-xl font-semibold">
                  Top 5 OWASP Categories + Developer Training
                </h2>
                <p className="mt-1 text-sm text-gray-600">
                  Most frequent OWASP categories per application with training guidance.
                </p>
              </div>

              {/* Tabs */}
              <div className="flex flex-wrap gap-2">
                {projectsInResponse.map((p) => (
                  <button
                    key={p}
                    onClick={() => setTop5Tab(p)}
                    className={[
                      "rounded-full border px-3 py-1 text-sm font-medium",
                      top5Tab === p
                        ? "border-blue-600 bg-blue-600 text-white"
                        : "bg-white text-gray-700 hover:bg-gray-50",
                    ].join(" ")}
                  >
                    {PROJECT_LABELS[p] ?? p}
                  </button>
                ))}
              </div>
            </div>



            <div className="mt-4 grid grid-cols-1 gap-3">
              {(top5[top5Tab] || []).map((item, idx) => (
                <div
                  key={`${item.owasp}-${idx}`}
                  className="rounded-lg border bg-gray-50 p-4"
                >
                  <div className="flex flex-col gap-2 md:flex-row md:items-start md:justify-between">
                    <div>
                      <div className="text-base font-semibold">{item.owasp}</div>
                      <div className="text-sm text-gray-600">
                        Count:{" "}
                        <span className="font-medium">{item.count}</span>
                      </div>
                    </div>

                    <div className="text-xs text-gray-500 md:text-right">
                      Training guidance
                    </div>
                  </div>

                  <div className="mt-3 rounded-md border bg-white p-3 text-sm leading-relaxed text-gray-800">
                    {item.training}
                  </div>
                </div>
              ))}

              {(top5[top5Tab] || []).length === 0 && (
                <div className="text-sm text-gray-500">
                  No Top 5 data for this project.
                </div>
              )}
            </div>
          </div>
        )}

        {/* Filters */}
        {Object.keys(data).length > 0 && (
          <div className="mb-4 flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold">All vulnerabilities</h2>
              <p className="text-sm text-gray-600">
                Filter tables by application.
              </p>
            </div>

            <div className="flex items-center gap-2">
              <label className="text-sm text-gray-700">Project</label>

              <select
                value={projectFilter}
                onChange={(e) => setProjectFilter(e.target.value)}
                className="rounded-md border bg-white p-2 text-sm"
              >
                <option value="all">All Projects</option>
                <option value="webgoat">WebGoat</option>
                <option value="juice-shop">Juice Shop</option>
              </select>
            </div>
          </div>
        )}

        {loading && (
          <p className="text-blue-600">Analyzing… please wait</p>
        )}

        {/* OWASP Tables */}
        <div className="space-y-6">
          {Object.entries(data).map(([owasp, vulns]) => {
            const filtered =
              projectFilter === "all"
                ? vulns
                : vulns.filter((v) => v.project === projectFilter);

            if (filtered.length === 0) return null;

            return (
              <div
                key={owasp}
                className="rounded-xl border bg-white p-4 shadow-sm"
              >
                <div className="mb-3 flex flex-col gap-1 md:flex-row md:items-end md:justify-between">
                  <div>
                    <h3 className="text-xl font-semibold">
                      {owasp}{" "}
                      <span className="text-gray-500">
                        ({filtered.length})
                      </span>
                    </h3>
                    <p className="text-sm text-gray-600">
                      Vulnerabilities classified into this OWASP category.
                    </p>
                  </div>
                </div>

                <div className="overflow-x-auto rounded-lg border">
                  <table className="w-full table-auto text-sm">
                    <thead className="bg-gray-100">
                      <tr>
                        <th className="border-b p-2 text-left">Key</th>
                        <th className="border-b p-2 text-left">Message</th>
                        <th className="border-b p-2 text-left">Severity</th>
                        <th className="border-b p-2 text-left">Project</th>
                        <th className="border-b p-2 text-left">Mapping</th>
                      </tr>
                    </thead>

                    <tbody>
                      {filtered.map((v) => (
                        <tr
                          key={v.key}
                          className="cursor-pointer odd:bg-white even:bg-gray-50 hover:bg-blue-50"
                          onClick={() => setSelectedVuln(v)}
                        >
                          <td className="border-b p-2 align-top font-mono text-xs">
                            {v.key}
                          </td>

                          <td className="border-b p-2 align-top">
                            {v.message}
                          </td>

                          <td className="border-b p-2 align-top">
                            <span
                              className={[
                                "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium",
                                severityBadge(v.severity),
                              ].join(" ")}
                            >
                              {v.severity}
                            </span>
                          </td>

                          <td className="border-b p-2 align-top">
                            {PROJECT_LABELS[v.project] ?? v.project}
                          </td>

                          <td className="border-b p-2 align-top text-gray-700">
                            {v.source}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <p className="mt-2 text-xs text-gray-500">
                  Tip: click a row to open detailed, per-application guidance and
                  mitigation for that vulnerability.
                </p>
              </div>
            );
          })}
        </div>

        {Object.keys(data).length === 0 && !loading && (
          <div className="mt-10 text-center text-gray-500">
            Upload reports to see results.
          </div>
        )}
      </div>
    </div>
  );
}
