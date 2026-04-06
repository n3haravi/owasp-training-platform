"use client";

import { useEffect, useState } from "react";
import { fetchWithAuth, clearToken } from "../lib/apiClient";
import { useRouter } from "next/navigation";

export default function CisoDashboard() {
  const [apps, setApps] = useState<any[]>([]);
  const [projects, setProjects] = useState<any[]>([]);
  const [devStats, setDevStats] = useState<any[]>([]);
  const [activeTab, setActiveTab] = useState("management");

  const [newAppName, setNewAppName] = useState("");
  const [newAppTech, setNewAppTech] = useState("");
  const [newProjName, setNewProjName] = useState("");
  const [newProjAppId, setNewProjAppId] = useState("");

  const [bulkCount, setBulkCount] = useState(1);
  const [bulkSkill, setBulkSkill] = useState("Fresher");
  const [bulkProjectId, setBulkProjectId] = useState("");
  const [generatedCreds, setGeneratedCreds] = useState<any[] | null>(null);

  const router = useRouter();

  const loadData = async () => {
    try {
      const [appData, projData, dashData] = await Promise.all([
        fetchWithAuth("/ciso/applications"),
        fetchWithAuth("/ciso/projects"),
        fetchWithAuth("/ciso/dashboard"),
      ]);
      setApps(appData);
      setProjects(projData);
      setDevStats(dashData);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleCreateApp = async (e: React.FormEvent) => {
    e.preventDefault();
    await fetchWithAuth("/ciso/applications", {
      method: "POST",
      body: JSON.stringify({ name: newAppName, technology: newAppTech }),
    });
    setNewAppName("");
    setNewAppTech("");
    loadData();
  };

  const handleCreateProject = async (e: React.FormEvent) => {
    e.preventDefault();
    await fetchWithAuth("/ciso/projects", {
      method: "POST",
      body: JSON.stringify({ name: newProjName, application_id: parseInt(newProjAppId) }),
    });
    setNewProjName("");
    setNewProjAppId("");
    loadData();
  };

  const handleBulkCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await fetchWithAuth("/ciso/developers/bulk-create", {
      method: "POST",
      body: JSON.stringify({
        count: bulkCount,
        skill_level: bulkSkill,
        project_id: parseInt(bulkProjectId),
      }),
    });
    setGeneratedCreds(res.credentials);
    loadData();
  };

  const handleLogout = () => {
    clearToken();
    router.push("/");
  };

  return (
    <div className="flex min-h-screen items-stretch bg-gray-50 text-slate-800">
      {/* Sidebar */}
      <div className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col items-start p-6 text-slate-200">
        <h2 className="text-xl font-bold mb-8 text-white">CISO Portal</h2>
        <button 
          onClick={() => setActiveTab("management")}
          className={`w-full text-left py-2 px-3 rounded-lg mb-2 ${activeTab === "management" ? "bg-blue-600 text-white" : "hover:bg-slate-800"}`}
        >
          App & Project Sync
        </button>
        <button 
          onClick={() => setActiveTab("dev_progress")}
          className={`w-full text-left py-2 px-3 rounded-lg ${activeTab === "dev_progress" ? "bg-blue-600 text-white" : "hover:bg-slate-800"}`}
        >
          Developer Progress
        </button>
        
        <div className="flex-grow"></div>
        <button onClick={handleLogout} className="mt-auto w-full py-2 hover:bg-slate-800 rounded-lg text-red-400">
          Logout
        </button>
      </div>

      {/* Main content */}
      <div className="flex-1 p-8 overflow-y-auto">
        <div className="max-w-6xl mx-auto space-y-8">
          
          {activeTab === "management" && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
              {/* Application Form */}
              <div className="bg-white p-6 shadow-sm border rounded-2xl">
                <h3 className="text-lg font-bold mb-4">Create Application</h3>
                <form onSubmit={handleCreateApp} className="space-y-4">
                  <input type="text" value={newAppName} onChange={e => setNewAppName(e.target.value)} placeholder="App Name (e.g. Healthcare)" className="w-full p-2 border rounded-md bg-gray-50" required />
                  <input type="text" value={newAppTech} onChange={e => setNewAppTech(e.target.value)} placeholder="Technology (e.g. .NET)" className="w-full p-2 border rounded-md bg-gray-50" required />
                  <button type="submit" className="w-full bg-blue-600 text-white p-2 rounded-md font-medium hover:bg-blue-700 transition">Create App</button>
                </form>

                <div className="mt-6 flex flex-wrap gap-2">
                  {apps.map(a => (
                    <span key={a.id} className="bg-slate-100 px-3 py-1 text-sm rounded-full border">
                      {a.name} ({a.technology})
                    </span>
                  ))}
                </div>
              </div>

              {/* Project Form */}
              <div className="bg-white p-6 shadow-sm border rounded-2xl">
                <h3 className="text-lg font-bold mb-4">Create Project</h3>
                <form onSubmit={handleCreateProject} className="space-y-4">
                  <input type="text" value={newProjName} onChange={e => setNewProjName(e.target.value)} placeholder="Project Name" className="w-full p-2 border rounded-md bg-gray-50" required />
                  <select value={newProjAppId} onChange={e => setNewProjAppId(e.target.value)} className="w-full p-2 border rounded-md bg-gray-50 text-slate-700" required>
                    <option value="" disabled>Select Application</option>
                    {apps.map(a => <option key={a.id} value={a.id}>{a.name}</option>)}
                  </select>
                  <button type="submit" className="w-full bg-indigo-600 text-white p-2 rounded-md font-medium hover:bg-indigo-700 transition">Create Project</button>
                </form>
                
                <div className="mt-6 flex flex-wrap gap-2">
                  {projects.map(p => (
                    <span key={p.id} className="bg-slate-100 px-3 py-1 text-sm rounded-full border">
                      {p.name}
                    </span>
                  ))}
                </div>
              </div>

              {/* Bulk Create Devs */}
              <div className="bg-white p-6 shadow-sm border rounded-2xl md:col-span-2">
                <h3 className="text-lg font-bold mb-4">Auto-Generate & Allocate Developers</h3>
                <form onSubmit={handleBulkCreate} className="space-y-4 md:space-y-0 md:flex md:gap-4 items-end">
                  <div className="flex-1">
                    <label className="text-xs font-semibold text-slate-500 mb-1 block">Developer Count</label>
                    <input type="number" min={1} max={100} value={bulkCount} onChange={e => setBulkCount(parseInt(e.target.value))} className="w-full p-2 border rounded-md bg-gray-50" required />
                  </div>
                  <div className="flex-1">
                    <label className="text-xs font-semibold text-slate-500 mb-1 block">Skill Level</label>
                    <select value={bulkSkill} onChange={e => setBulkSkill(e.target.value)} className="w-full p-2 border rounded-md bg-gray-50 text-slate-700">
                      <option value="Fresher">Fresher</option>
                      <option value="Intermediate">Intermediate</option>
                      <option value="Expert">Expert</option>
                    </select>
                  </div>
                  <div className="flex-1">
                    <label className="text-xs font-semibold text-slate-500 mb-1 block">Assign to Project</label>
                    <select value={bulkProjectId} onChange={e => setBulkProjectId(e.target.value)} className="w-full p-2 border rounded-md bg-gray-50 text-slate-700" required>
                      <option value="" disabled>Select Project</option>
                      {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
                    </select>
                  </div>
                  <div>
                    <button type="submit" className="w-full bg-emerald-600 text-white px-6 py-2 rounded-md font-medium hover:bg-emerald-700 transition">
                      Generate
                    </button>
                  </div>
                </form>

                {generatedCreds && (
                  <div className="mt-6 bg-slate-50 p-4 border rounded-xl overflow-x-auto">
                    <h4 className="text-sm font-bold text-slate-800 mb-3">Generated Credentials</h4>
                    <table className="min-w-full text-sm text-left">
                      <thead className="text-slate-500 font-semibold border-b">
                        <tr><th className="pb-2">Username</th><th className="pb-2">Password</th><th className="pb-2">Skill Level</th></tr>
                      </thead>
                      <tbody>
                        {generatedCreds.map((dev, i) => (
                          <tr key={i} className="border-b last:border-0 hover:bg-white transition-colors">
                            <td className="py-2 text-blue-600">{dev.username}</td>
                            <td className="py-2 font-mono text-slate-600">{dev.password}</td>
                            <td className="py-2"><span className="bg-slate-200 px-2 py-0.5 rounded-full text-xs">{dev.skill_level}</span></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab === "dev_progress" && (
            <div className="bg-white p-6 shadow-sm border rounded-2xl">
              <h3 className="text-xl font-bold mb-6 text-slate-800">Developer Tracking Dashboard</h3>
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-slate-50 text-slate-600 text-sm font-semibold uppercase tracking-wider border-b">
                      <th className="p-4">Developer</th>
                      <th className="p-4">Skill Level</th>
                      <th className="p-4">Assigned Projects</th>
                      <th className="p-4">Training Status</th>
                      <th className="p-4 w-1/4">Overall Progress</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y text-slate-700 text-sm">
                    {devStats.map(d => (
                      <tr key={d.id} className="hover:bg-slate-50 transition">
                        <td className="p-4 font-medium text-slate-900">{d.username}</td>
                        <td className="p-4">{d.skill_level}</td>
                        <td className="p-4">
                          <div className="flex flex-wrap gap-1">
                            {d.projects.map((p: any) => (
                              <span key={p.id} className="bg-blue-100 text-blue-800 px-2 py-0.5 rounded-md text-xs">{p.name}</span>
                            ))}
                          </div>
                        </td>
                        <td className="p-4">
                          <span className={`px-2 py-1 rounded-full text-xs font-semibold ${
                            d.training_status === "Completed" ? "bg-emerald-100 text-emerald-800" : 
                            d.training_status === "In Progress" ? "bg-amber-100 text-amber-800" : 
                            "bg-gray-100 text-gray-800"
                          }`}>
                            {d.training_status}
                          </span>
                        </td>
                        <td className="p-4">
                          <div className="flex items-center gap-3">
                            <div className="flex-1 h-2 rounded-full border bg-slate-200 overflow-hidden">
                              <div className="h-full bg-blue-500 rounded-full" style={{ width: `${d.progress}%` }}></div>
                            </div>
                            <span className="text-xs font-semibold">{d.progress}%</span>
                          </div>
                        </td>
                      </tr>
                    ))}
                    {devStats.length === 0 && (
                      <tr><td colSpan={5} className="p-6 text-center text-slate-500">No developers found. Generate some in App Sync.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

        </div>
      </div>
    </div>
  );
}
