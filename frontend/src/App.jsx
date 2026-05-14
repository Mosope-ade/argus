import { useEffect, useMemo, useState } from "react";

import { useSession } from "./hooks/useSession";
import { useWebSocket } from "./hooks/useWebSocket";

import { api } from "./api/argus";

import AlertFeed from "./components/AlertFeed";
import IncidentView from "./components/IncidentView";
import IncidentCard from "./components/IncidentCard";
import AuthScreen from "./components/AuthScreen";

export default function App() {
  const {
    isAuthenticated,
    login,
    logout,
    loading,
    error,
  } = useSession();

  const ws = useWebSocket();

  const [incidents, setIncidents] = useState([]);
  const [activeIncident, setActiveIncident] = useState(null);

  useEffect(() => {
    if (!isAuthenticated) return;

    const loadIncidents = async () => {
      try {
        const res = await api.getIncidents();
        const data = await res.json();

        setIncidents(data.incidents || []);

        if (data.incidents?.length > 0) {
          setActiveIncident(data.incidents[0]);
        }
      } catch (err) {
        console.error(err);
      }
    };

    loadIncidents();
  }, [isAuthenticated]);

  useEffect(() => {
    const latest = ws.lastMessage;

    if (!latest) return;

    if (latest.type === "done" && latest.report) {
      setIncidents((prev) => [
        latest.report,
        ...prev,
      ]);

      setActiveIncident(latest.report);
    }
  }, [ws.lastMessage]);

  const agentSteps = useMemo(() => {
    return ws.messages.filter(
      (m) =>
        m.type === "plan" ||
        m.type === "result" ||
        m.type === "error" ||
        m.type === "done"
    );
  }, [ws.messages]);

  if (loading) {
    return (
      <div className="h-screen bg-[#080c12] flex items-center justify-center text-[#e2e8f0] font-mono">
        Loading...
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <AuthScreen
        login={login}
        loading={loading}
        error={error}
      />
    );
  }

  return (
    <div className="h-screen bg-[#080c12] text-[#e2e8f0] overflow-hidden">
      {/* HEADER */}
      <header className="h-16 border-b border-[#1a2535] px-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl tracking-widest font-bold">
            ARGUS
          </h1>

          <div className="text-xs text-[#4a6080] font-mono mt-1">
            AI-Driven Security Investigation Platform
          </div>
        </div>

        <div className="flex items-center gap-4">
          <div className="text-sm font-mono text-[#00ff9d]">
            ● Monitoring Active
          </div>

          <div className="text-xs font-mono text-[#4a6080]">
            WS: {ws.status}
          </div>

          <button
            onClick={logout}
            className="border border-[#1a2535] px-3 py-1 text-sm font-mono hover:border-[#ff3c5a] hover:text-[#ff3c5a]"
          >
            Logout
          </button>
        </div>
      </header>

      {/* MAIN */}
      <main className="grid grid-cols-[30%_70%] h-[calc(100vh-64px)]">
        {/* LEFT PANEL */}
        <div className="border-r border-[#1a2535] overflow-hidden">
          <AlertFeed wsMessages={ws.messages} />
        </div>

        {/* RIGHT PANEL */}
        <div className="overflow-y-auto">
          {activeIncident ? (
            <IncidentView
              incident={activeIncident}
              agentSteps={agentSteps}
            />
          ) : (
            <div className="p-6">
              <div className="text-[#4a6080] font-mono mb-4">
                No active incidents
              </div>

              <div className="grid gap-4">
                {incidents.map((incident) => (
                  <IncidentCard
                    key={incident.incident_id}
                    incident={incident}
                    onSelect={setActiveIncident}
                  />
                ))}
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}