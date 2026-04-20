"use client";

import { useEffect, useMemo, useState } from "react";
import { fetchWithAuth } from "../../lib/apiClient";
import { useRouter } from "next/navigation";

type AppItem = { id: number; name: string; technology: string };
type Grouped = Record<
  string,
  Array<{
    key?: string;
    rule?: string;
    severity?: string;
    component?: string;
    message?: string;
    owasp: string;
    classification_source?: string;
    training?: string;
    file?: string;
  }>
>;

function severityColor(sev?: string) {
  const s = (sev || "").toUpperCase();
  if (s === "BLOCKER" || s === "CRITICAL") {
    return "bg-rose-50 text-rose-700 ring-rose-200";
  }
  if (s === "MAJOR") return "bg-amber-50 text-amber-700 ring-amber-200";
  if (s === "MINOR") return "bg-sky-50 text-sky-700 ring-sky-200";
  if (s === "INFO") return "bg-slate-50 text-slate-700 ring-slate-200";
  return "bg-slate-50 text-slate-700 ring-slate-200";
}

function prettySource(src?: string) {
  if (!src) return "";
  if (src === "keyword-based") return "keyword";
  if (src === "ai-cached") return "ai (cached)";
  if (src === "ai-error-fallback") return "ai (fallback)";
  return src;
}

export default function UploadPage() {
  const [file, setFile] = useState<File | null>(null);
  const [message, setMessage] = useState("");
  const [error, setError] = useState<string>("");
  const [apps, setApps] = useState<AppItem[]>([]);
  const [applicationId, setApplicationId] = useState<string>("");
  const [grouped, setGrouped] = useState<Grouped>({});
  const [processedCount, setProcessedCount] = useState<number | null>(null);
  const [projectsTouched, setProjectsTouched] = useState<Record<string, number>>({});
  const [groupedCounts, setGroupedCounts] = useState<Record<string, number>>({});
  const [truncatedCats, setTruncatedCats] = useState<string[]>([]);
  const [maxReturnedPerCat, setMaxReturnedPerCat] = useState<number | null>(null);
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<
    "ALL" | "BLOCKER" | "CRITICAL" | "MAJOR" | "MINOR" | "INFO" | "UNKNOWN"
  >("ALL");
  const [openCats, setOpenCats] = useState<Record<string, boolean>>({});
  const router = useRouter();
  
  useEffect(() => {
    (async () => {
      try {
        const appData = await fetchWithAuth("/ciso/applications");
        setApps(appData || []);
        if (!applicationId && Array.isArray(appData) && appData.length > 0) {
          setApplicationId(String(appData[0].id));
        }
      } catch (e) {
        console.error(e);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const owaspOrder = useMemo(
    () => [
      "A01: Broken Access Control",
      "A02: Cryptographic Failures",
      "A03: Injection",
      "A04: Insecure Design",
      "A05: Security Misconfiguration",
      "A06: Vulnerable & Outdated Components",
      "A07: Identification & Authentication Failures",
      "A08: Software & Data Integrity Failures",
      "A09: Security Logging & Monitoring Failures",
      "A10: Server-Side Request Forgery",
    ],
    []
  );

  const sortedCategories = useMemo(() => {
    const keys = Object.keys(grouped || {});
    const rank = new Map(owaspOrder.map((k, i) => [k, i]));
    return keys.sort((a, b) => (rank.get(a) ?? 999) - (rank.get(b) ?? 999));
  }, [grouped, owaspOrder]);

  const filteredGrouped = useMemo(() => {
    const q = query.trim().toLowerCase();
    const out: Grouped = {};
    for (const cat of Object.keys(grouped || {})) {
      const rows = grouped[cat] || [];
      const filtered = rows.filter((v) => {
        const sev = (v.severity || "UNKNOWN").toUpperCase();
        if (severityFilter !== "ALL" && sev !== severityFilter) return false;
        if (!q) return true;
        const hay =
          `${v.message || ""} ${v.rule || ""} ${v.component || ""} ${v.severity || ""} ${v.file || ""}`.toLowerCase();
        return hay.includes(q);
      });
      if (filtered.length) out[cat] = filtered;
    }
    return out;
  }, [grouped, query, severityFilter]);

  const sortedFilteredCategories = useMemo(() => {
    const keys = Object.keys(filteredGrouped || {});
    const rank = new Map(owaspOrder.map((k, i) => [k, i]));
    return keys.sort((a, b) => (rank.get(a) ?? 999) - (rank.get(b) ?? 999));
  }, [filteredGrouped, owaspOrder]);

  const handleUpload = async (e?: React.FormEvent) => {
    e?.preventDefault();
    setMessage("");
    setError("");
    setGrouped({});
    setProcessedCount(null);
    setProjectsTouched({});
    setGroupedCounts({});
    setTruncatedCats([]);
    setMaxReturnedPerCat(null);

    if (!applicationId) {
      alert("Please select an application");
      return;
    }

    if (!file) {
      alert("Please select a file");
      return;
    }

    const formData = new FormData();
    formData.append("application_id", applicationId);
    formData.append("files", file);

    try {
      const data = await fetchWithAuth("/upload", {
        method: "POST",
        body: formData,
      });
      const processed = Number(data.vulnerabilities_processed ?? 0);
      setMessage(
        `Uploaded & analyzed. Processed ${processed} issue${processed === 1 ? "" : "s"}.`
      );
      setGrouped(data.grouped_by_owasp_top10 || {});
      setProcessedCount(processed);
      setProjectsTouched(data.projects_created_or_reused || {});
      setGroupedCounts(data.grouped_counts || {});
      setTruncatedCats(data.truncated_categories || []);
      setMaxReturnedPerCat(
        typeof data.max_returned_per_category === "number"
          ? data.max_returned_per_category
          : null
      );
      setQuery("");
      setSeverityFilter("ALL");
      setOpenCats({});
    } catch (err) {
      console.error("UPLOAD ERROR:", err);
      setError(err instanceof Error ? err.message : "Upload/analysis failed");
    }
  };
   return (
    <div className="min-h-screen bg-gradient-to-b from-slate-50 to-white text-slate-900">
      <div className="mx-auto w-full max-w-6xl px-4 py-10">
        <div className="mb-6 flex items-start justify-between gap-4">
          <div>
            <h2 className="text-2xl font-bold tracking-tight">Upload SonarQube Report</h2>
            <p className="mt-1 text-sm text-slate-600">
              Upload a SonarQube issues JSON. We’ll classify and group findings by OWASP Top 10.
            </p>
          </div>
          <button
            onClick={() => router.push("/ciso")}
            className="shrink-0 rounded-lg border bg-white px-3 py-2 text-sm font-medium text-slate-700 shadow-sm hover:bg-slate-50"
          >
            ← Back
          </button>
        </div>

        <div className="rounded-2xl border bg-white p-6 shadow-sm">
          <form onSubmit={handleUpload} className="grid grid-cols-1 gap-4 md:grid-cols-12">
            <div className="md:col-span-5">
              <label className="block text-sm font-medium text-slate-700">
                Application
              </label>
              <select
                value={applicationId}
                onChange={(e) => setApplicationId(e.target.value)}
                className="mt-2 w-full rounded-lg border bg-white px-3 py-2 text-sm text-slate-900 shadow-sm focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-100"
                required
              >
                {apps.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name} ({a.technology})
                  </option>
                ))}
              </select>
              <p className="mt-2 text-xs text-slate-500">
                Findings will be stored against this application.
              </p>
            </div>

            <div className="md:col-span-5">
              <label className="block text-sm font-medium text-slate-700">
                SonarQube JSON report
              </label>
              <input
                type="file"
                accept=".json"
                onChange={(e) => setFile(e.target.files?.[0] || null)}
                className="mt-2 w-full rounded-lg border bg-white px-3 py-2 text-sm shadow-sm file:mr-3 file:rounded-md file:border-0 file:bg-slate-100 file:px-3 file:py-2 file:text-sm file:font-medium file:text-slate-700 hover:file:bg-slate-200"
              />
              <p className="mt-2 text-xs text-slate-500">
                Tip: export issues in JSON with an `issues` array.
              </p>
            </div>

            <div className="md:col-span-2 md:flex md:items-end">
              <button
                type="submit"
                className="w-full rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-200"
              >
                Upload & Analyze
              </button>
            </div>
          </form>

          {message && (
            <div className="mt-4 rounded-xl border bg-slate-50 px-4 py-3 text-sm text-slate-700">
              {message}
            </div>
          )}

          {error && (
            <div className="mt-4 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-800">
              {error}
            </div>
          )}
        </div>

        {(processedCount !== null || sortedFilteredCategories.length > 0) && (
          <div className="mt-8">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
              <div>
                <h3 className="text-lg font-bold">Findings</h3>
                <p className="mt-1 text-sm text-slate-600">
                  Grouped by OWASP Top 10. Use search to quickly locate issues.
                </p>
              </div>
              <div className="w-full sm:max-w-md">
                <label className="block text-xs font-medium text-slate-600">
                  Search
                </label>
                <input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="message, rule, component, severity, file…"
                  className="mt-2 w-full rounded-lg border bg-white px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-100"
                />
              </div>
            </div>

            <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-3">
              <div className="rounded-2xl border bg-white p-4 shadow-sm">
                <div className="text-xs font-semibold text-slate-500">Processed</div>
                <div className="mt-1 text-2xl font-bold text-slate-900">
                  {processedCount ?? 0}
                </div>
                <div className="mt-1 text-xs text-slate-600">
                  Total issues parsed from the report.
                </div>
              </div>
              <div className="rounded-2xl border bg-white p-4 shadow-sm md:col-span-2">
                <div className="text-xs font-semibold text-slate-500">
                  Projects created / reused
                </div>
                <div className="mt-2 flex flex-wrap gap-2">
                  {Object.keys(projectsTouched || {}).length === 0 ? (
                    <span className="text-sm text-slate-600">—</span>
                  ) : (
                    Object.entries(projectsTouched).map(([name, id]) => (
                      <span
                        key={name}
                        className="rounded-full border bg-slate-50 px-3 py-1 text-xs font-semibold text-slate-700"
                      >
                        {name} (#{id})
                      </span>
                    ))
                  )}
                </div>
              </div>
            </div>

            {truncatedCats.length > 0 && (
              <div className="mt-3 rounded-2xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900">
                Large report: some categories are truncated in the UI (showing first{" "}
                {maxReturnedPerCat ?? "N"} items). Counts still reflect the full report.
              </div>
            )}

            <div className="mt-4 flex flex-col gap-3 rounded-2xl border bg-white p-4 shadow-sm sm:flex-row sm:items-center sm:justify-between">
              <div className="flex flex-wrap items-center gap-2">
                <div className="text-xs font-semibold text-slate-600">Severity</div>
                {(
                  [
                    "ALL",
                    "BLOCKER",
                    "CRITICAL",
                    "MAJOR",
                    "MINOR",
                    "INFO",
                    "UNKNOWN",
                  ] as const
                ).map((sev) => (
                  <button
                    key={sev}
                    type="button"
                    onClick={() => setSeverityFilter(sev)}
                    className={`rounded-full px-3 py-1 text-xs font-semibold ring-1 ring-inset transition ${
                      severityFilter === sev
                        ? "bg-blue-600 text-white ring-blue-600"
                        : "bg-white text-slate-700 ring-slate-200 hover:bg-slate-50"
                    }`}
                  >
                    {sev}
                  </button>
                ))}
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={() => {
                    const next: Record<string, boolean> = {};
                    for (const cat of sortedFilteredCategories) next[cat] = true;
                    setOpenCats(next);
                  }}
                  className="rounded-lg border bg-white px-3 py-2 text-xs font-semibold text-slate-700 shadow-sm hover:bg-slate-50"
                >
                  Expand all categories
                </button>
                <button
                  type="button"
                  onClick={() => {
                    const next: Record<string, boolean> = {};
                    for (const cat of sortedFilteredCategories) next[cat] = false;
                    setOpenCats(next);
                  }}
                  className="rounded-lg border bg-white px-3 py-2 text-xs font-semibold text-slate-700 shadow-sm hover:bg-slate-50"
                >
                  Collapse all categories
                </button>
              </div>
            </div>

            <div className="mt-5 space-y-5">
              {sortedFilteredCategories.length === 0 && (
                <div className="rounded-2xl border bg-white p-6 text-sm text-slate-700 shadow-sm">
                  No findings to display (either the report had 0 issues, or your current
                  filters/search removed all results).
                </div>
              )}
              {sortedFilteredCategories.map((cat) => {
                const rows = (filteredGrouped[cat] || []).slice(0, 100);
                const total = (filteredGrouped[cat] || []).length;
                const isOpen = openCats[cat] ?? true;
                return (
                  <details
                    key={cat}
                    open={isOpen}
                    onToggle={(e) => {
                      const open = (e.currentTarget as HTMLDetailsElement).open;
                      setOpenCats((prev) => ({ ...prev, [cat]: open }));
                    }}
                    className="rounded-2xl border bg-white shadow-sm"
                  >
                    <summary className="cursor-pointer list-none">
                      <div className="flex flex-col gap-2 border-b bg-slate-50 px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
                        <div className="flex items-center gap-3">
                          <div className="h-9 w-1.5 rounded-full bg-blue-600" />
                          <div>
                            <div className="text-sm font-semibold text-slate-900">
                              {cat}
                            </div>
                            <div className="text-xs text-slate-600">
                              {total} finding{total === 1 ? "" : "s"}
                              {total > 100 ? " (showing first 100)" : ""}
                            </div>
                          </div>
                        </div>
                        <div className="text-xs text-slate-600">
                          Columns: Severity • Message • Rule • Component • File • Classified
                        </div>
                      </div>
                    </summary>

                    <div className="hidden grid-cols-12 gap-3 px-5 py-3 text-xs font-semibold text-slate-500 md:grid">
                      <div className="col-span-2">Severity</div>
                      <div className="col-span-4">Message</div>
                      <div className="col-span-2">Rule</div>
                      <div className="col-span-2">Component</div>
                      <div className="col-span-1">File</div>
                      <div className="col-span-1">Source</div>
                    </div>

                    <div className="divide-y">
                      {rows.map((v, idx) => {
                        const sev = (v.severity || "UNKNOWN").toUpperCase();
                        const src = prettySource(v.classification_source);
                        return (
                          <details
                            key={`${v.key || idx}`}
                            className="group px-5 py-4 hover:bg-slate-50"
                          >
                            <summary className="cursor-pointer list-none">
                              <div className="grid grid-cols-1 gap-3 md:grid-cols-12 md:items-start">
                                <div className="md:col-span-2">
                                  <span
                                    className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ring-inset ${severityColor(
                                      sev
                                    )}`}
                                  >
                                    {sev}
                                  </span>
                                </div>

                                <div className="md:col-span-4">
                                  <div className="text-sm font-semibold text-slate-900">
                                    {v.message || "Unknown issue"}
                                  </div>
                                  <div className="mt-1 text-xs text-slate-600 md:hidden">
                                    {v.rule ? `Rule: ${v.rule}` : null}
                                    {v.component ? ` • ${v.component}` : null}
                                    {v.file ? ` • ${v.file}` : null}
                                    {src ? ` • ${src}` : null}
                                  </div>
                                </div>

                                <div className="hidden text-xs text-slate-700 md:col-span-2 md:block">
                                  <div className="truncate">{v.rule || "—"}</div>
                                </div>

                                <div className="hidden text-xs text-slate-700 md:col-span-2 md:block">
                                  <div className="truncate">{v.component || "—"}</div>
                                </div>

                                <div className="hidden text-xs text-slate-700 md:col-span-1 md:block">
                                  <div className="truncate">{v.file || "—"}</div>
                                </div>

                                <div className="hidden text-xs text-slate-700 md:col-span-1 md:block">
                                  <div className="truncate">{src || "—"}</div>
                                </div>
                              </div>
                            </summary>

                            <div className="mt-3 grid grid-cols-1 gap-3 rounded-xl border bg-white p-4 text-sm text-slate-800 md:grid-cols-12">
                              <div className="md:col-span-6">
                                <div className="text-xs font-semibold text-slate-500">
                                  Details
                                </div>
                                <div className="mt-1 space-y-1 text-xs text-slate-700">
                                  <div>
                                    <span className="font-semibold">OWASP:</span>{" "}
                                    {v.owasp}
                                  </div>
                                  {v.rule && (
                                    <div>
                                      <span className="font-semibold">Rule:</span>{" "}
                                      {v.rule}
                                    </div>
                                  )}
                                  {v.component && (
                                    <div>
                                      <span className="font-semibold">
                                        Component:
                                      </span>{" "}
                                      {v.component}
                                    </div>
                                  )}
                                  {v.file && (
                                    <div>
                                      <span className="font-semibold">File:</span>{" "}
                                      {v.file}
                                    </div>
                                  )}
                                  {src && (
                                    <div>
                                      <span className="font-semibold">
                                        Classified via:
                                      </span>{" "}
                                      {src}
                                    </div>
                                  )}
                                </div>
                              </div>
                              <div className="md:col-span-6">
                                <div className="text-xs font-semibold text-slate-500">
                                  Guidance
                                </div>
                                <div className="mt-1 text-xs text-slate-700">
                                  {v.training ||
                                    "Follow OWASP Top 10 secure coding guidance for this category."}
                                </div>
                              </div>
                            </div>
                          </details>
                        );
                      })}
                    </div>
                  </details>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
