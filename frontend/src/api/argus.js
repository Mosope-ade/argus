const BASE_URL = "http://localhost:8001";

export const api = {
  health: () =>
    fetch(`${BASE_URL}/api/health`, {
      credentials: "include",
    }),

  login: (pw) =>
    fetch(`${BASE_URL}/api/login`, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: pw }),
    }),

  logout: () =>
    fetch(`${BASE_URL}/api/logout`, {
      method: "POST",
      credentials: "include",
    }),

  getAlerts: () =>
    fetch(`${BASE_URL}/api/alerts`, {
      credentials: "include",
    }),

  getIncidents: () =>
    fetch(`${BASE_URL}/api/incidents`, {
      credentials: "include",
    }),

  getIncident: (id) =>
    fetch(`${BASE_URL}/api/incidents/${id}`, {
      credentials: "include",
    }),
};