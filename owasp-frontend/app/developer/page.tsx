"use client";

import { useEffect, useState } from "react";
import { fetchWithAuth, clearToken } from "../lib/apiClient";
import { useRouter } from "next/navigation";

export default function DeveloperDashboard() {
  const [data, setData] = useState<any>(null);
  const [progress, setProgress] = useState(0);
  const [trainingStatus, setTrainingStatus] = useState("Not Started");
  const [saving, setSaving] = useState(false);

  const router = useRouter();

  const loadData = async () => {
    try {
      const res = await fetchWithAuth("/dev/me");
      setData(res);
      setProgress(res.user.progress);
      setTrainingStatus(res.user.training_status);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleSaveProgress = async () => {
    setSaving(true);
    await fetchWithAuth("/dev/progress", {
      method: "POST",
      body: JSON.stringify({ progress, training_status: trainingStatus }),
    });
    setSaving(false);
    loadData();
  };

  const handleLogout = () => {
    clearToken();
    router.push("/");
  };

  if (!data) return <div className="p-8 text-center text-slate-500">Loading Developer Portal...</div>;

  return (
    <div className="flex min-h-screen flex-col bg-slate-50">
      <header className="bg-slate-900 px-8 py-4 shadow-md text-white flex justify-between items-center">
        <div>
          <h1 className="text-xl font-bold tracking-tight">Developer Portal</h1>
          <p className="text-sm text-slate-400">Welcome, {data.user.username} <span className="bg-slate-700 ml-2 px-2 py-0.5 rounded-full text-xs">{data.user.skill_level}</span></p>
        </div>
        <button onClick={handleLogout} className="px-4 py-2 border border-slate-700 bg-slate-800 rounded-md hover:bg-slate-700 transition">Logout</button>
      </header>

      <main className="flex-1 max-w-5xl w-full mx-auto p-8 grid grid-cols-1 md:grid-cols-3 gap-8">
        
        <div className="md:col-span-2 space-y-6">
          <div className="bg-white p-6 shadow-sm border border-slate-200 rounded-2xl">
            <h2 className="text-lg font-bold text-slate-800 mb-4">Assigned Projects</h2>
            <div className="grid grid-cols-1 gap-4">
              {data.projects.map((p: any) => (
                <div key={p.id} className="p-4 rounded-xl border bg-slate-50 flex items-center justify-between">
                  <span className="font-semibold text-slate-700">{p.name}</span>
                </div>
              ))}
              {data.projects.length === 0 && <p className="text-slate-500 text-sm">No assigned projects yet.</p>}
            </div>
          </div>

          <div className="bg-gradient-to-br from-indigo-900 to-slate-900 p-8 shadow-lg rounded-2xl text-white">
            <h2 className="text-xl font-bold mb-4">Training Material ({data.user.skill_level})</h2>
            <p className="text-slate-300 leading-relaxed font-light">{data.training_material}</p>
          </div>
        </div>

        <div className="space-y-6">
          <div className="bg-white p-6 shadow-sm border border-slate-200 rounded-2xl">
            <h2 className="text-lg font-bold text-slate-800 mb-6">Track Your Progress</h2>
            
            <div className="mb-6">
              <label className="block text-sm font-semibold text-slate-600 mb-3">Overall Progress ({progress}%)</label>
              <input 
                type="range" 
                min="0" max="100" 
                value={progress} 
                onChange={e => setProgress(parseInt(e.target.value))}
                className="w-full accent-blue-600"
              />
            </div>

            <div className="mb-6">
              <label className="block text-sm font-semibold text-slate-600 mb-3">Training Status</label>
              <select 
                value={trainingStatus} 
                onChange={e => setTrainingStatus(e.target.value)}
                className="w-full p-2.5 rounded-lg border bg-slate-50 text-slate-700 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              >
                <option value="Not Started">Not Started</option>
                <option value="In Progress">In Progress</option>
                <option value="Completed">Completed</option>
              </select>
            </div>

            <button 
              onClick={handleSaveProgress} 
              disabled={saving}
              className={`w-full py-3 rounded-lg font-bold text-white transition ${saving ? "bg-blue-400" : "bg-blue-600 hover:bg-blue-700"}`}
            >
              {saving ? "Saving..." : "Update Progress"}
            </button>
          </div>
        </div>

      </main>
    </div>
  );
}
