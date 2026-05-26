import { useEffect, useMemo, useState } from "react";

import { api } from "./api/argus";
import { useSession } from "./hooks/useSession";
import { useWebSocket } from "./hooks/useWebSocket";

import AlertFeed from "./components/AlertFeed";
import IncidentView from "./components/IncidentView";
import AuthScreen from "./components/AuthScreen";

export default function App() {
  const { isAuthenticated, login, logout, loading, error } = useSession();
  const ws = useWebSocket();

  const [incidents, setIncidents] = useState({});
  const [activeIncidentId, setActiveIncidentId] = useState(null);
  const [investigatingAlerts, setInvestigatingAlerts] = useState(new Set());
  const isInvestigating = investigatingAlerts.size > 0;

  // Request notification permission once on login
  useEffect(() => {
    if (!isAuthenticated) return;
    if ("Notification" in window && Notification.permission === "default") {
      Notification.requestPermission();
    }
  }, [isAuthenticated]);

  // Load existing incidents on mount
  useEffect(() => {
    if (!isAuthenticated) return;
    const load = async () => {
      try {
        const res = await api.getIncidents();
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

    if (latest.type === "new_alert" && latest.alert?.alert_id) {
      setInvestigatingAlerts((prev) => new Set([...prev, latest.alert.alert_id]));
    }

    if (latest.type === "done" && latest.report) {
      const report = latest.report;
      setIncidents((prev) => ({ ...prev, [report.incident_id]: report }));
      setActiveIncidentId((prev) => prev ?? report.incident_id);
      setInvestigatingAlerts((prev) => {
        const next = new Set(prev);
        next.delete(latest.alert_id);
        return next;
      });

      // Browser push notification
      if ("Notification" in window && Notification.permission === "granted") {
        const severityEmoji = {
          CRITICAL: "🔴",
          HIGH:     "🟠",
          MEDIUM:   "🟡",
          LOW:      "🟢",
        }[report.severity] ?? "⚪";

        const n = new Notification(
          `${severityEmoji} Argus — Investigation Complete`,
          {
            body: `${report.incident_id} · ${report.attack_type}\n${
              report.recommendations?.[0] ?? "View report for details"
            }`,
            icon: "/favicon.ico",
            tag:  report.incident_id,
            requireInteraction: report.severity === "CRITICAL",
          }
        );

        n.onclick = () => {
          window.focus();
          setActiveIncidentId(report.incident_id);
          n.close();
        };
      }
    }

    if (latest.type === "error") {
      setInvestigatingAlerts(new Set());
    }
  }, [ws.lastMessage]);

  const activeIncident = activeIncidentId ? incidents[activeIncidentId] : null;

  const agentSteps = useMemo(() => {
    const relevant = (m) =>
      m.type === "plan" || m.type === "result" || m.type === "error";
    if (!activeIncident) return ws.messages.filter(relevant);
    return ws.messages.filter(
      (m) => relevant(m) && (!m.alert_id || m.alert_id === activeIncident.alert_id)
    );
  }, [ws.messages, activeIncident]);

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
          <div className={`text-sm font-mono ${ws.status === "connected" ? "text-[#00ff9d]" : "text-[#ff3c5a]"}`}>
            ● {ws.status === "connected" ? "Monitoring Active" : "Disconnected"}
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
              onClose={() => setActiveIncidentId(null)}
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
                      <div key={`${step.type}-${step.action || step.summary || step.message || i}`} className="text-[#4a6080] font-mono text-xs mb-1">
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