export const API_BASE = "http://127.0.0.1:8000";

export const getToken = () => typeof window !== "undefined" ? localStorage.getItem("token") : null;
export const setToken = (token: string) => typeof window !== "undefined" && localStorage.setItem("token", token);
export const clearToken = () => typeof window !== "undefined" && localStorage.removeItem("token");

export async function fetchWithAuth(endpoint: string, options: RequestInit = {}) {
  const token = getToken();
  const headers = new Headers(options.headers || {});
  
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  
  if (!(options.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    if ((response.status === 401 || response.status === 403) && !endpoint.includes("/auth/login")) {
      clearToken();
      if (typeof window !== "undefined") window.location.href = "/auth";
    }
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail || "API Request failed");
  }
  return response.json();
}
