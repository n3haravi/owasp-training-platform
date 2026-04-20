"use client";

import { useEffect, useMemo, useState } from "react";
import { fetchWithAuth, clearToken } from "../lib/apiClient";
import { useRouter } from "next/navigation";

function clamp(n: number, min: number, max: number) {
  return Math.min(max, Math.max(min, n));
}

function levelForXp(xp: number) {
  // Simple curve: each level requires a bit more XP.
  // L1: 0-199, L2: 200-449, L3: 450-749, ...
  const thresholds = [0, 200, 450, 750, 1100, 1500, 1950, 2450, 3000, 3600];
  let lvl = 1;
  for (let i = 0; i < thresholds.length; i++) {
    if (xp >= thresholds[i]) lvl = i + 1;
  }
  const curBase = thresholds[lvl - 1] ?? 0;
  const nextBase = thresholds[lvl] ?? (curBase + 700);
  return { level: lvl, curBase, nextBase };
}

function formatBadge(b: { id: string; name: string; desc: string }) {
  return b;
}

export default function DeveloperDashboard() {
  const [dash, setDash] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [activeProjectId, setActiveProjectId] = useState<number | null>(null);
  const [activeOwasp, setActiveOwasp] = useState<string | null>(null);
  const [moduleContent, setModuleContent] = useState<any>(null);
  const [loadingModule, setLoadingModule] = useState(false);
  const [error, setError] = useState<string>("");

  const router = useRouter();

  const loadData = async () => {
    setLoading(true);
    try {
      const res = await fetchWithAuth("/dev/dashboard");
      setDash(res);
      const firstProj = (res.projects || [])[0];
      if (firstProj && activeProjectId === null) setActiveProjectId(firstProj.id);
    } catch (e: any) {
      setError(e?.message || "Failed to load dashboard");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const projects = dash?.projects || [];
  const modules = dash?.modules || [];

  const completedModules = Number(dash?.totals?.completed_modules ?? 0);
  const totalModules = Number(dash?.totals?.total_modules ?? 0);

  const totalFindings = useMemo(() => {
    const ps = dash?.projects || [];
    let sum = 0;
    for (const p of ps) {
      const cc = p.category_counts || {};
      for (const k of Object.keys(cc)) sum += Number(cc[k] || 0);
    }
    return sum;
  }, [dash]);

  const xp = useMemo(() => {
    // Award XP for learning (module completion) + a tiny boost for project exposure (findings).
    return completedModules * 200 + Math.min(500, Math.floor(totalFindings / 25) * 10);
  }, [completedModules, totalFindings]);

  const lvl = useMemo(() => levelForXp(xp), [xp]);
  const levelPct = useMemo(() => {
    const denom = Math.max(1, lvl.nextBase - lvl.curBase);
    return Math.round(((xp - lvl.curBase) / denom) * 100);
  }, [xp, lvl.curBase, lvl.nextBase]);

  const [streak, setStreak] = useState<number>(0);
  const [lastComplete, setLastComplete] = useState<string>("");

  useEffect(() => {
    try {
      const key = `owasp_streak_${dash?.user?.username || "dev"}`;
      const stored = JSON.parse(localStorage.getItem(key) || "{}");
      setStreak(Number(stored.streak || 0));
      setLastComplete(String(stored.last || ""));
    } catch {
      // ignore
    }
  }, [dash?.user?.username]);

  const badges = useMemo(() => {
    const b = [];
    if (completedModules >= 1)
      b.push(formatBadge({ id: "first", name: "First Fix", desc: "Complete your first module" }));
    if (completedModules >= 5)
      b.push(formatBadge({ id: "five", name: "Patch Apprentice", desc: "Complete 5 modules" }));
    if (completedModules >= 10)
      b.push(formatBadge({ id: "ten", name: "OWASP Ranger", desc: "Complete 10 modules" }));
    if (streak >= 3)
      b.push(formatBadge({ id: "streak3", name: "On a Roll", desc: "3‑day learning streak" }));
    if (streak >= 7)
      b.push(formatBadge({ id: "streak7", name: "Unstoppable", desc: "7‑day learning streak" }));
    return b;
  }, [completedModules, streak]);

  const activeProject = useMemo(
    () => projects.find((p: any) => p.id === activeProjectId) || null,
    [projects, activeProjectId]
  );

  const activeProjectModules = useMemo(() => {
    if (!activeProjectId) return [];
    return modules.filter((m: any) => m.project_id === activeProjectId);
  }, [modules, activeProjectId]);

  const fetchModule = async (projectId: number, owasp: string) => {
    setError("");
    setActiveOwasp(owasp);
    setModuleContent(null);
    setLoadingModule(true);
    try {
      const res = await fetchWithAuth(
        `/dev/modules/content?project_id=${projectId}&owasp=${encodeURIComponent(owasp)}`
      );
      setModuleContent(res);
    } catch (e: any) {
      setError(e.message || "Failed to load module");
    } finally {
      setLoadingModule(false);
    }
  };

  const completeModule = async () => {
    if (!activeProjectId || !activeOwasp) return;
    setError("");
    await fetchWithAuth("/dev/modules/complete", {
      method: "POST",
      body: JSON.stringify({ project_id: activeProjectId, owasp: activeOwasp }),
    });

    // Update local streak (lightweight gamification).
    try {
      const today = new Date();
      const todayKey = today.toISOString().slice(0, 10);
      const key = `owasp_streak_${dash?.user?.username || "dev"}`;
      const stored = JSON.parse(localStorage.getItem(key) || "{}");
      const last = String(stored.last || "");
      let nextStreak = Number(stored.streak || 0);

      const y = new Date(today);
      y.setDate(y.getDate() - 1);
      const yKey = y.toISOString().slice(0, 10);

      if (last === todayKey) {
        // already counted today
      } else if (last === yKey) {
        nextStreak += 1;
      } else {
        nextStreak = 1;
      }

      localStorage.setItem(key, JSON.stringify({ last: todayKey, streak: nextStreak }));
      setLastComplete(todayKey);
      setStreak(nextStreak);
    } catch {
      // ignore
    }

    await loadData();
  };

  const handleLogout = () => {
    clearToken();
    router.push("/");
  };

  if (loading && !dash) {
    return (
      <div className="p-8 text-center text-slate-500">Loading Developer Portal...</div>
    );
  }
  if (!dash) {
    return (
      <div className="min-h-screen bg-slate-50 p-8">
        <div className="mx-auto max-w-xl rounded-2xl border bg-white p-6 text-slate-800 shadow-sm">
          <div className="text-lg font-bold">Developer Portal</div>
          <div className="mt-2 text-sm text-slate-600">
            Could not load your dashboard.
          </div>
          {error && (
            <div className="mt-4 rounded-xl border border-rose-200 bg-rose-50 p-3 text-sm text-rose-800">
              {error}
            </div>
          )}
          <button
            onClick={() => {
              setError("");
              loadData();
            }}
            className="mt-5 rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-700"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen flex-col bg-slate-50">
      <header className="bg-slate-900 px-8 py-4 shadow-md text-white flex justify-between items-center">
        <div>
          <h1 className="text-xl font-bold tracking-tight">Developer Portal</h1>
          <p className="text-sm text-slate-400">
            Welcome, {dash.user.username}{" "}
            <span className="bg-slate-700 ml-2 px-2 py-0.5 rounded-full text-xs">
              {dash.user.skill_level || "Developer"}
            </span>
          </p>
        </div>
        <button
          onClick={handleLogout}
          className="px-4 py-2 border border-slate-700 bg-slate-800 rounded-md hover:bg-slate-700 transition"
        >
          Logout
        </button>
      </header>

      <main className="flex-1 max-w-6xl w-full mx-auto p-8 grid grid-cols-1 lg:grid-cols-12 gap-8">
        <div className="lg:col-span-4 space-y-6">
          <div className="rounded-2xl border border-slate-200 bg-gradient-to-br from-slate-900 via-slate-900 to-indigo-900 p-6 text-white shadow-sm">
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="text-xs font-semibold text-slate-300">LEVEL</div>
                <div className="mt-1 text-3xl font-extrabold tracking-tight">
                  {lvl.level}
                </div>
                <div className="mt-1 text-sm text-slate-200">
                  {xp} XP • Streak {streak} day{streak === 1 ? "" : "s"}
                </div>
              </div>
              <div className="text-right">
                <div className="text-xs font-semibold text-slate-300">STATUS</div>
                <div className="mt-1 inline-flex items-center rounded-full bg-white/10 px-3 py-1 text-xs font-semibold">
                  {dash.user.training_status}
                </div>
                <div className="mt-2 text-xs text-slate-300">
                  {completedModules}/{totalModules} modules
                </div>
              </div>
            </div>

            <div className="mt-5">
              <div className="flex items-center justify-between text-xs text-slate-200">
                <span>XP to next level</span>
                <span>
                  {clamp(xp - lvl.curBase, 0, 999999)}/{Math.max(1, lvl.nextBase - lvl.curBase)}
                </span>
              </div>
              <div className="mt-2 h-2 w-full rounded-full bg-white/10 overflow-hidden">
                <div
                  className="h-full bg-emerald-400"
                  style={{ width: `${clamp(levelPct, 0, 100)}%` }}
                />
              </div>
              <div className="mt-3 text-xs text-slate-300">
                Last completion: {lastComplete || "—"}
              </div>
            </div>
          </div>

          <div className="bg-white p-6 shadow-sm border border-slate-200 rounded-2xl">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-bold text-slate-800">Badges</h2>
              <span className="text-xs text-slate-500">{badges.length} earned</span>
            </div>
            {badges.length === 0 ? (
              <div className="mt-3 text-sm text-slate-600">
                Complete your first module to unlock badges.
              </div>
            ) : (
              <div className="mt-4 grid grid-cols-1 gap-3">
                {badges.map((b) => (
                  <div key={b.id} className="rounded-xl border bg-slate-50 p-4">
                    <div className="text-sm font-semibold text-slate-900">{b.name}</div>
                    <div className="mt-1 text-xs text-slate-600">{b.desc}</div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="bg-white p-6 shadow-sm border border-slate-200 rounded-2xl">
            <h2 className="text-lg font-bold text-slate-800">Missions</h2>
            <div className="mt-4 space-y-3">
              <div className="rounded-xl border bg-slate-50 p-4">
                <div className="text-sm font-semibold text-slate-900">
                  Daily: complete 1 module
                </div>
                <div className="mt-1 text-xs text-slate-600">
                  Reward: 200 XP • Keep your streak alive
                </div>
              </div>
              <div className="rounded-xl border bg-slate-50 p-4">
                <div className="text-sm font-semibold text-slate-900">
                  Weekly: complete 5 modules
                </div>
                <div className="mt-1 text-xs text-slate-600">
                  Reward: 1000 XP • Unlock “Patch Apprentice”
                </div>
              </div>
            </div>
          </div>

          <div className="bg-white p-6 shadow-sm border border-slate-200 rounded-2xl">
            <h2 className="text-lg font-bold text-slate-800 mb-4">Assigned Projects</h2>
            <div className="space-y-2">
              {projects.map((p: any) => (
                <button
                  key={p.id}
                  onClick={() => {
                    setActiveProjectId(p.id);
                    setActiveOwasp(null);
                    setModuleContent(null);
                  }}
                  className={`w-full rounded-xl border p-4 text-left transition ${
                    activeProjectId === p.id
                      ? "border-blue-300 bg-blue-50"
                      : "bg-slate-50 hover:bg-slate-100"
                  }`}
                >
                  <div className="font-semibold text-slate-900">{p.name}</div>
                  <div className="mt-1 text-xs text-slate-600">
                    {Object.keys(p.category_counts || {}).length} OWASP categories
                  </div>
                </button>
              ))}
              {projects.length === 0 && (
                <p className="text-slate-500 text-sm">No assigned projects yet.</p>
              )}
            </div>
          </div>

          <div className="bg-white p-6 shadow-sm border border-slate-200 rounded-2xl">
            <h2 className="text-lg font-bold text-slate-800 mb-4">Training Modules</h2>
            {!activeProject ? (
              <div className="text-sm text-slate-600">Select a project to view modules.</div>
            ) : activeProjectModules.length === 0 ? (
              <div className="text-sm text-slate-600">
                No vulnerabilities uploaded for this project yet.
              </div>
            ) : (
              <div className="space-y-2">
                {activeProjectModules.map((m: any) => (
                  <button
                    key={`${m.project_id}-${m.owasp}`}
                    onClick={() => fetchModule(m.project_id, m.owasp)}
                    className={`w-full rounded-xl border p-4 text-left transition ${
                      activeOwasp === m.owasp
                        ? "border-slate-900 bg-white"
                        : "bg-slate-50 hover:bg-slate-100"
                    }`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="truncate font-semibold text-slate-900">{m.owasp}</div>
                        <div className="mt-1 text-xs text-slate-600">
                          {m.finding_count} finding{m.finding_count === 1 ? "" : "s"}
                        </div>
                      </div>
                      {m.completed ? (
                        <span className="rounded-full bg-emerald-600 px-2 py-1 text-xs font-semibold text-white">
                          Completed
                        </span>
                      ) : (
                        <span className="rounded-full bg-slate-200 px-2 py-1 text-xs font-semibold text-slate-700">
                          Pending
                        </span>
                      )}
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="lg:col-span-8">
          <div className="bg-white p-6 shadow-sm border border-slate-200 rounded-2xl min-h-[420px]">
            <h2 className="text-lg font-bold text-slate-800">
              {activeProject ? activeProject.name : "Training"}
            </h2>

            {error && (
              <div className="mt-4 rounded-xl border border-rose-200 bg-rose-50 p-3 text-sm text-rose-800">
                {error}
              </div>
            )}

            {!activeProject ? (
              <div className="mt-4 text-sm text-slate-600">
                Select a project to see the OWASP training modules assigned to you.
              </div>
            ) : !activeOwasp ? (
              <div className="mt-4 text-sm text-slate-600">
                Select an OWASP module to view AI-guided remediation and mitigation training.
              </div>
            ) : loadingModule ? (
              <div className="mt-6 text-sm text-slate-600">Loading module…</div>
            ) : !moduleContent ? (
              <div className="mt-6 text-sm text-slate-600">No module loaded.</div>
            ) : (
              <div className="mt-6 space-y-6">
                <div className="rounded-xl border bg-slate-50 p-4">
                  <div className="text-sm font-semibold text-slate-900">
                    {moduleContent.title || activeOwasp}
                  </div>
                  <div className="mt-2 text-sm text-slate-700 leading-relaxed">
                    {moduleContent.overview}
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="rounded-xl border bg-white p-4">
                    <div className="text-sm font-semibold text-slate-900">Remediation</div>
                    <div className="mt-2 text-sm text-slate-700 leading-relaxed">
                      {moduleContent.remediation}
                    </div>
                  </div>
                  <div className="rounded-xl border bg-white p-4">
                    <div className="text-sm font-semibold text-slate-900">Mitigation</div>
                    <div className="mt-2 text-sm text-slate-700 leading-relaxed">
                      {moduleContent.mitigation}
                    </div>
                  </div>
                </div>

                <div className="rounded-xl border bg-white p-4">
                  <div className="text-sm font-semibold text-slate-900">Checklist</div>
                  <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-slate-700">
                    {(moduleContent.checklist || []).map((c: string, idx: number) => (
                      <li key={idx}>{c}</li>
                    ))}
                  </ul>
                </div>

                <div className="flex items-center justify-between gap-3">
                  <div className="text-xs text-slate-600">
                    Mark this module completed to update your progress.
                  </div>
                  <button
                    onClick={completeModule}
                    className="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-semibold text-white hover:bg-emerald-700"
                  >
                    Mark Completed
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}

