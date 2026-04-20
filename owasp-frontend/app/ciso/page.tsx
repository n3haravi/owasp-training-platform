"use client";

import { useEffect, useMemo, useState } from "react";
import { fetchWithAuth, clearToken } from "../lib/apiClient";
import { useRouter } from "next/navigation";

type ProjectItem = {
  id: number;
  name: string;
  application_id?: number;
  status?: string;
};
type AppItem = { id: number; name: string; technology: string };
type DevItem = {
  id: number;
  username: string;
  full_name: string;
  skill_level?: string;
  training_status?: string;
  progress?: number;
  projects: Array<{ id: number; name: string }>;
};

export default function CisoDashboard() {
  const [apps, setApps] = useState<AppItem[]>([]);
  const [projects, setProjects] = useState<ProjectItem[]>([]);
  const [developers, setDevelopers] = useState<DevItem[]>([]);
  const [activeTab, setActiveTab] = useState<"projects" | "developers">("projects");

  const [newProjName, setNewProjName] = useState("");

  const [assignProjectId, setAssignProjectId] = useState<string>("");
  const [selectedDeveloperIds, setSelectedDeveloperIds] = useState<Record<number, boolean>>(
    {}
  );
  const [assignMessage, setAssignMessage] = useState<string>("");

  const router = useRouter();

  const loadData = async () => {
    const [appData, projData, devData] = await Promise.all([
      fetchWithAuth("/ciso/applications"),
      fetchWithAuth("/ciso/projects"),
      fetchWithAuth("/ciso/developers"),
    ]);
    setApps(appData || []);
    setProjects(projData || []);
    setDevelopers(devData || []);
    if (!assignProjectId && Array.isArray(projData) && projData.length > 0) {
      setAssignProjectId(String(projData[0].id));
    }
  };

  useEffect(() => {
    loadData().catch(console.error);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleCreateProject = async (e: React.FormEvent) => {
    e.preventDefault();
    const defaultAppId = apps?.[0]?.id;
    if (!defaultAppId) throw new Error("No application found");
    await fetchWithAuth("/ciso/projects", {
      method: "POST",
      body: JSON.stringify({
        name: newProjName,
        application_id: defaultAppId,
      }),
    });
    setNewProjName("");
    await loadData();
  };

  const handleAssign = async (e: React.FormEvent) => {
    e.preventDefault();
    setAssignMessage("");
    const pid = parseInt(assignProjectId);
    if (!pid) return;

    const developerIds = Object.entries(selectedDeveloperIds)
      .filter(([, v]) => v)
      .map(([id]) => parseInt(id));

    const res = await fetchWithAuth(`/ciso/projects/${pid}/assign`, {
      method: "POST",
      body: JSON.stringify({ developer_ids: developerIds }),
    });
    setAssignMessage(`Assigned ${res.assigned?.length ?? 0} developer(s).`);
    await loadData();
  };

  const handleLogout = () => {
    clearToken();
    router.push("/");
  };

  const devsByProjectId = useMemo(() => {
    const m = new Map<number, DevItem[]>();
    for (const p of projects) m.set(p.id, []);
    for (const d of developers) {
      for (const p of d.projects || []) {
        const arr = m.get(p.id) || [];
        arr.push(d);
        m.set(p.id, arr);
      }
    }
    return m;
  }, [developers, projects]);

  return (
    <div className="flex min-h-screen items-stretch bg-gray-50 text-slate-800">
      <div className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col items-start p-6 text-slate-200">
        <h2 className="text-xl font-bold mb-8 text-white">CISO Portal</h2>

        <button
          onClick={() => setActiveTab("projects")}
          className={`w-full text-left py-2 px-3 rounded-lg mb-2 ${
            activeTab === "projects" ? "bg-blue-600 text-white" : "hover:bg-slate-800"
          }`}
        >
          Projects
        </button>

        <button
          onClick={() => setActiveTab("developers")}
          className={`w-full text-left py-2 px-3 rounded-lg ${
            activeTab === "developers" ? "bg-blue-600 text-white" : "hover:bg-slate-800"
          }`}
        >
          Developers
        </button>

        <div className="flex-grow"></div>

        <button
          onClick={() => router.push("/ciso/upload")}
          className="w-full text-left py-2 px-3 rounded-lg mb-2 hover:bg-slate-800"
        >
          Upload Vulnerabilities
        </button>

        <button
          onClick={handleLogout}
          className="mt-auto w-full py-2 hover:bg-slate-800 rounded-lg text-red-400"
        >
          Logout
        </button>
      </div>

      <div className="flex-1 p-8 overflow-y-auto">
        <div className="max-w-6xl mx-auto space-y-8">
          {activeTab === "projects" && (
            <div className="space-y-8">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                <div className="bg-white p-6 shadow-sm border rounded-2xl">
                  <h3 className="text-lg font-bold mb-1">Create Project</h3>
                  <p className="text-sm text-slate-600 mb-4">
                    Projects are also auto-created from uploaded report filenames.
                  </p>
                  <form onSubmit={handleCreateProject} className="space-y-4">
                    <input
                      type="text"
                      value={newProjName}
                      onChange={(e) => setNewProjName(e.target.value)}
                      placeholder="Project Name (e.g. webgoat-issues)"
                      className="w-full p-2 border rounded-md bg-gray-50"
                      required
                    />
                    <button
                      type="submit"
                      className="w-full bg-indigo-600 text-white p-2 rounded-md font-medium hover:bg-indigo-700 transition disabled:opacity-60"
                      disabled={!apps?.[0]?.id}
                    >
                      Create Project
                    </button>
                    {!apps?.[0]?.id && (
                      <div className="text-xs text-rose-600">
                        No application found. Start the backend once to seed the default
                        application.
                      </div>
                    )}
                  </form>
                </div>

                <div className="bg-white p-6 shadow-sm border rounded-2xl">
                  <h3 className="text-lg font-bold mb-1">Assign Developers</h3>
                  <p className="text-sm text-slate-600 mb-4">
                    Assign real developers (accounts that exist / logged in) to a project.
                  </p>
                  <form onSubmit={handleAssign} className="space-y-4">
                    <select
                      value={assignProjectId}
                      onChange={(e) => setAssignProjectId(e.target.value)}
                      className="w-full p-2 border rounded-md bg-gray-50 text-slate-700"
                      required
                    >
                      {projects.map((p) => (
                        <option key={p.id} value={p.id}>
                          {p.name}
                        </option>
                      ))}
                    </select>

                    <div className="max-h-56 overflow-auto rounded-xl border bg-gray-50 p-3">
                      {developers.length === 0 ? (
                        <div className="text-sm text-slate-600">
                          No developers found yet. Have developers log in once to appear
                          here.
                        </div>
                      ) : (
                        <div className="space-y-2">
                          {developers.map((d) => (
                            <label
                              key={d.id}
                              className="flex items-center justify-between gap-3 rounded-lg bg-white px-3 py-2 border"
                            >
                              <div className="min-w-0">
                                <div className="truncate text-sm font-semibold text-slate-800">
                                  {d.full_name}{" "}
                                  <span className="text-slate-500 font-normal">
                                    ({d.username})
                                  </span>
                                </div>
                                <div className="text-xs text-slate-600">
                                  Skill: {d.skill_level || "—"} • Progress:{" "}
                                  {d.progress ?? 0}%
                                </div>
                              </div>
                              <input
                                type="checkbox"
                                checked={!!selectedDeveloperIds[d.id]}
                                onChange={(e) =>
                                  setSelectedDeveloperIds((prev) => ({
                                    ...prev,
                                    [d.id]: e.target.checked,
                                  }))
                                }
                                className="h-4 w-4"
                              />
                            </label>
                          ))}
                        </div>
                      )}
                    </div>

                    <button
                      className="w-full bg-emerald-600 text-white px-6 py-2 rounded-md font-medium hover:bg-emerald-700 disabled:opacity-60"
                      disabled={!assignProjectId}
                    >
                      Assign Selected Developers
                    </button>
                    {assignMessage && (
                      <div className="text-sm text-slate-700">{assignMessage}</div>
                    )}
                  </form>
                </div>
              </div>

              <div className="bg-white p-6 shadow-sm border rounded-2xl">
                <h3 className="text-lg font-bold mb-4">
                  Projects (includes uploaded reports)
                </h3>
                {projects.length === 0 ? (
                  <div className="text-sm text-slate-600">
                    No projects yet. Upload a report to auto-create one, or create a
                    project above.
                  </div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {projects.map((p) => {
                      const assigned = devsByProjectId.get(p.id) || [];
                      return (
                        <div key={p.id} className="rounded-xl border bg-gray-50 p-4">
                          <div className="flex items-start justify-between gap-3">
                            <div className="min-w-0">
                              <div className="truncate font-semibold text-slate-900">
                                {p.name}
                              </div>
                              <div className="text-xs text-slate-600">
                                Status: {p.status || "Active"}
                              </div>
                            </div>
                            <span className="rounded-full bg-slate-900 px-2 py-1 text-xs font-semibold text-white">
                              {assigned.length} dev
                            </span>
                          </div>

                          <div className="mt-3 text-xs text-slate-700">
                            <div className="font-semibold text-slate-600 mb-1">
                              Assigned developers
                            </div>
                            {assigned.length === 0 ? (
                              <div className="text-slate-500">None assigned yet</div>
                            ) : (
                              <div className="flex flex-wrap gap-2">
                                {assigned.map((d) => (
                                  <span
                                    key={d.id}
                                    className="rounded-full border bg-white px-2 py-1"
                                  >
                                    {d.username}
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab === "developers" && (
            <div className="bg-white p-6 shadow-sm border rounded-2xl">
              <h3 className="text-lg font-bold mb-4">Developer Progress</h3>
              {developers.length === 0 ? (
                <div className="text-sm text-slate-600">
                  No developers yet. Developers will appear after they log in.
                </div>
              ) : (
                <div className="space-y-3">
                  {developers.map((d) => (
                    <div
                      key={d.id}
                      className="rounded-xl border bg-gray-50 p-4 flex items-start justify-between gap-4"
                    >
                      <div className="min-w-0">
                        <div className="font-semibold text-slate-900 truncate">
                          {d.full_name}{" "}
                          <span className="text-slate-500 font-normal">
                            ({d.username})
                          </span>
                        </div>
                        <div className="text-sm text-slate-700 mt-1">
                          Skill: {d.skill_level || "—"} • Status:{" "}
                          {d.training_status || "—"}
                        </div>
                        <div className="text-xs text-slate-600 mt-2">
                          Projects:{" "}
                          {d.projects?.length
                            ? d.projects.map((p) => p.name).join(", ")
                            : "None"}
                        </div>
                      </div>
                      <div className="shrink-0 text-right">
                        <div className="text-sm font-semibold text-slate-900">
                          {d.progress ?? 0}%
                        </div>
                        <div className="mt-2 h-2 w-32 rounded-full bg-slate-200 overflow-hidden">
                          <div
                            className="h-full bg-blue-600"
                            style={{
                              width: `${Math.min(
                                100,
                                Math.max(0, d.progress ?? 0)
                              )}%`,
                            }}
                          />
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

