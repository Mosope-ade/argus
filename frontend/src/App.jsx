import { useEffect, useMemo, useState } from "react";

import { useSession } from "./hooks/useSession";
import { useWebSocket } from "./hooks/useWebSocket";

import AlertFeed from "./components/AlertFeed";
import IncidentView from "./components/IncidentView";
import AuthScreen from "./components/AuthScreen";

export default function App() {
  const { isAuthenticated, login, logout, loading, error } = useSession();
  const ws = useWebSocket();

  // incident_id → report dict
  const [incidents, setIncidents] = useState({});
  // The incident currently shown in the right panel
  const [activeIncidentId, setActiveIncidentId] = useState(null);

  const [isInvestigating, setIsInvestigating] = useState(false);

  // Load existing incidents on mount
  useEffect(() => {
    if (!isAuthenticated) return;
    const load = async () => {
      try {
        const res = await fetch("http://localhost:8001/api/incidents", {
          credentials: "include",
        });
        const data = await res.json();
        const map = {};
        for (const inc of data.incidents || []) {
          map[inc.incident_id] = inc;
        }
        setIncidents(map);
        const ids = Object.keys(map);
        if (ids.length > 0) setActiveIncidentId(ids[0]);
      } catch (err) {
        console.error(err);
      }
    };
    load();
  }, [isAuthenticated]);

  // Handle incoming WS events
  useEffect(() => {
    const latest = ws.lastMessage;
    if (!latest) return;

    if (latest.type === "new_alert") {
      setIsInvestigating(true);
    }

    if (latest.type === "done" && latest.report) {
      const report = latest.report;
      setIncidents((prev) => ({ ...prev, [report.incident_id]: report }));
      setActiveIncidentId((prev) => prev ?? report.incident_id);
      setIsInvestigating(false);
    }

    if (latest.type === "error") {
      setIsInvestigating(false);
    }
  }, [ws.lastMessage]);

  // Agent steps scoped to the active incident's alert
  const activeIncident = activeIncidentId ? incidents[activeIncidentId] : null;

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
    return <AuthScreen login={login} loading={loading} error={error} />;
  }

  return (
    <div className="h-screen bg-[#080c12] text-[#e2e8f0] overflow-hidden">
      {/* HEADER */}
      <header className="h-16 border-b border-[#1a2535] px-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl tracking-widest font-bold">ARGUS</h1>
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
        {/* LEFT — Alert Feed */}
        <div className="border-r border-[#1a2535] overflow-hidden">
          <AlertFeed
            wsMessages={ws.messages}
            incidents={incidents}
            activeIncidentId={activeIncidentId}
            onSelectIncident={setActiveIncidentId}
            isAuthenticated={isAuthenticated}
          />
        </div>

        {/* RIGHT — Incident View */}
        <div className="overflow-y-auto">
          {activeIncident ? (
            <IncidentView
              incident={activeIncident}
              agentSteps={agentSteps}
            />
          ) : (
            <div className="h-full flex items-center justify-center">
              <div className="text-center">
                <div className={`font-mono text-4xl mb-4 ${
                  isInvestigating ? "text-[#00d4ff]" : "text-[#1a2535]"
                }`}>⬡</div>
                <div className="text-[#4a6080] font-mono text-sm">
                  {isInvestigating
                    ? "Investigation in progress..."
                    : "Waiting for alerts..."}
                </div>
                {isInvestigating && (
                  <div className="mt-6 text-left max-w-sm">
                    {agentSteps.slice(-3).map((step, i) => (
                      <div key={i} className="text-[#4a6080] font-mono text-xs mb-1">
                        {step.type === "plan" && (
                          <span>
                            <span className="text-[#00d4ff]">&gt; </span>
                            {step.action}
                          </span>
                        )}
                        {step.type === "result" && (
                          <span className="text-[#00ff9d]">&gt; {step.summary}</span>
                        )}
                        {step.type === "error" && (
                          <span className="text-[#ff3c5a]">&gt; {step.message}</span>
                        )}
                      </div>
                    ))}
                    <div className="text-[#00d4ff] font-mono text-xs mt-2 animate-pulse">
                      ▋
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}