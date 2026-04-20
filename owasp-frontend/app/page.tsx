"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { fetchWithAuth, setToken } from "./lib/apiClient";

export default function Home() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const router = useRouter();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    try {
      const res = await fetchWithAuth("/auth/login", {
        method: "POST",
        body: JSON.stringify({
          username: username.trim(),
          password: password.trim(),
        }),
      });
      setToken(res.access_token);
      router.push(res.role === "CISO" ? "/ciso" : "/developer");
    } catch (err: any) {
      setError(err.message || "Login failed");
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-slate-950 via-slate-900 to-slate-800 px-4 text-slate-100">
      <div className="w-full max-w-md rounded-2xl border border-slate-700/70 bg-slate-900/50 p-8 shadow-2xl backdrop-blur-xl">
        <h1 className="text-center text-3xl font-extrabold tracking-tight text-white">
          OWASP Training Platform
        </h1>
        <p className="mt-2 text-center text-sm text-slate-400">
          Sign in to access the CISO or Developer portal.
        </p>

        {error && (
          <div className="mt-6 rounded-xl border border-rose-500/40 bg-rose-500/10 p-3 text-center text-sm text-rose-200">
            {error}
          </div>
        )}

        <form onSubmit={handleLogin} className="mt-7 space-y-5">
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-300">
              Username
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full rounded-lg border border-slate-600 bg-slate-950/40 px-4 py-2.5 text-slate-200 placeholder-slate-500 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
              placeholder="e.g. admin"
              required
              autoComplete="username"
            />
          </div>

          <div>
            <label className="mb-1 block text-sm font-medium text-slate-300">
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-lg border border-slate-600 bg-slate-950/40 px-4 py-2.5 text-slate-200 placeholder-slate-500 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
              placeholder="••••••••"
              required
              autoComplete="current-password"
            />
          </div>

          <button
            type="submit"
            className="mt-2 w-full rounded-lg bg-blue-600 px-4 py-2.5 font-semibold tracking-wide text-white shadow-sm transition-colors hover:bg-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-slate-900"
          >
            Sign In
          </button>
        </form>
      </div>
    </div>
  );
}

