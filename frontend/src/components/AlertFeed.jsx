import { useEffect, useRef, useState } from "react";
import { api } from "../api/argus";

function relativeTime(timestamp) {
  const diff = Math.max(0, Math.floor((Date.now() - new Date(timestamp)) / 1000));
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  return `${Math.floor(diff / 3600)}h ago`;
}

const DISMISSED_KEY = "argus:dismissed_alerts";

function loadDismissed() {
  try {
    return new Set(JSON.parse(localStorage.getItem(DISMISSED_KEY) || "[]"));
  } catch {
    return new Set();
  }
}

function saveDismissed(set) {
  localStorage.setItem(DISMISSED_KEY, JSON.stringify([...set]));
}

export default function AlertFeed({
  wsMessages = [],
  incidents = {},
  activeIncidentId,
  onSelectIncident,
  isAuthenticated = false,
}) {
  const [alerts, setAlerts] = useState([]);
  const [alertToIncident, setAlertToIncident] = useState({});
  const [investigating, setInvestigating] = useState({});
  const [dismissed, setDismissed] = useState(loadDismissed);
  const [showDismissed, setShowDismissed] = useState(false);
  const [, setTick] = useState(0);
  const seenIds = useRef(new Set());

  useEffect(() => {
    const id = setInterval(() => setTick((t) => t + 1), 30000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    if (!isAuthenticated) return;

    const loadAlerts = async () => {
      try {
        const res = await api.getAlerts();
        if (res.status === 401) return;
        const data = await res.json();
        const fetched = data.alerts || [];
        setAlerts((prev) => {
          const existingIds = new Set(prev.map((a) => a.alert_id));
          const newOnes = fetched.filter((a) => !existingIds.has(a.alert_id));
          newOnes.forEach((a) => seenIds.current.add(a.alert_id));
          return newOnes.length > 0 ? [...newOnes, ...prev] : prev;
        });
      } catch (err) {
        console.error("Failed to load alerts:", err);
      }
    };

    loadAlerts();
    const interval = setInterval(loadAlerts, 30000);
    return () => clearInterval(interval);
  }, [isAuthenticated]);

  useEffect(() => {
    const latest = wsMessages[wsMessages.length - 1];
    if (!latest) return;

    if (latest.type === "new_alert" && latest.alert?.alert_id) {
      const id = latest.alert.alert_id;
      if (!seenIds.current.has(id)) {
        seenIds.current.add(id);
        setAlerts((prev) => [latest.alert, ...prev]);
      }
      setInvestigating((prev) => ({ ...prev, [id]: true }));
    }

    if (latest.type === "plan" && latest.alert_id) {
      setInvestigating((prev) => ({ ...prev, [latest.alert_id]: true }));
    }

    if (latest.type === "done" && latest.alert_id && latest.incident_id) {
      setInvestigating((prev) => ({ ...prev, [latest.alert_id]: false }));
      setAlertToIncident((prev) => ({
        ...prev,
        [latest.alert_id]: latest.incident_id,
      }));
    }

    if (latest.type === "error") {
      if (latest.alert_id) {
        setInvestigating((prev) => ({ ...prev, [latest.alert_id]: false }));
      } else {
        setInvestigating({});
      }
    }
  }, [wsMessages]);

  useEffect(() => {
    for (const report of Object.values(incidents)) {
      if (report.alert_id && report.incident_id) {
        setAlertToIncident((prev) => ({
          ...prev,
          [report.alert_id]: report.incident_id,
        }));
        setInvestigating((prev) => ({ ...prev, [report.alert_id]: false }));
      }
    }
  }, [incidents]);

  const resolveIncidentId = (alertId) =>
    alertToIncident[alertId] ??
    Object.values(incidents).find((r) => r.alert_id === alertId)?.incident_id;

  const dismissAlert = (alertId) => {
    setDismissed((prev) => {
      const next = new Set(prev);
      next.add(alertId);
      saveDismissed(next);
      return next;
    });
    const incidentId = resolveIncidentId(alertId);
    if (incidentId && incidentId === activeIncidentId) {
      onSelectIncident(null);
    }
  };

  const restoreAlert = (alertId) => {
    setDismissed((prev) => {
      const next = new Set(prev);
      next.delete(alertId);
      saveDismissed(next);
      return next;
    });
  };

  const removeAlert = async (alertId) => {
    try {
      await api.deleteAlert(alertId);
    } catch (err) {
      console.error("Failed to delete alert from backend:", err);
    }

    // Remove from local state
    setAlerts((prev) => prev.filter((a) => a.alert_id !== alertId));
    setDismissed((prev) => {
      const next = new Set(prev);
      next.delete(alertId);
      saveDismissed(next);
      return next;
    });
    const incidentId = resolveIncidentId(alertId);
    if (incidentId && incidentId === activeIncidentId) {
      onSelectIncident(null);
    }
  };

  const activeAlerts    = alerts.filter((a) => !dismissed.has(a.alert_id));
  const dismissedAlerts = alerts.filter((a) =>  dismissed.has(a.alert_id));

  const renderAlert = (alert, isDismissed = false) => {
    const isInvestigating = !!investigating[alert.alert_id];
    const incidentId      = alertToIncident[alert.alert_id];
    const isDone          = !!incidentId;
    const isActive        = incidentId === activeIncidentId;

    return (
      <div
        key={alert.alert_id}
        className={`p-4 border-b border-[#1a2535] transition-colors ${
          isActive ? "bg-[#0d1520]" : "hover:bg-[#0d1117]"
        } ${isDismissed ? "opacity-50" : ""}`}
      >
        <div className="flex items-start justify-between gap-2">
          {/* Left — alert info */}
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <span className={`flex-shrink-0 text-xs ${
                isInvestigating
                  ? "text-[#00d4ff] animate-pulse"
                  : isDone
                  ? "text-[#00ff9d]"
                  : "text-[#ff3c5a]"
              }`}>●</span>
              <span className="text-[#e2e8f0] font-mono text-sm truncate">
                {alert.search_name}
              </span>
            </div>
            <div className="mt-2 text-[#4a6080] font-mono text-xs">
              SRC: {alert.src_ip || "—"}
            </div>
            <div className="text-[#4a6080] font-mono text-xs">
              HOST: {alert.host || "—"}
            </div>
            <div className="mt-1 text-[#4a6080] font-mono text-xs">
              {alert.alert_id}
            </div>
            <div className="mt-1 text-[#4a6080] font-mono text-xs">
              {relativeTime(alert.timestamp)}
            </div>
          </div>

          {/* Right — action buttons */}
          <div className="flex flex-col items-end gap-2 flex-shrink-0 mt-1">

            {/* Primary action */}
            {isInvestigating ? (
              <span className="px-3 py-1 border border-[#00d4ff] text-[#00d4ff] text-xs font-mono opacity-50 cursor-not-allowed select-none">
                Investigating...
              </span>
            ) : isDone ? (
              <button
                onClick={() => onSelectIncident(incidentId)}
                className={`px-3 py-1 border text-xs font-mono transition-colors ${
                  isActive
                    ? "border-[#00ff9d] text-[#00ff9d] bg-[#00ff9d15]"
                    : "border-[#1a2535] text-[#00d4ff] hover:border-[#00d4ff]"
                }`}
              >
                {isActive ? "Viewing" : "Investigate"}
              </button>
            ) : (
              <span className="px-3 py-1 border border-[#1a2535] text-[#4a6080] text-xs font-mono">
                Queued
              </span>
            )}

            {/* Secondary action — dismiss or restore+remove */}
            {isDismissed ? (
              <div className="flex gap-3">
                <button
                  onClick={() => restoreAlert(alert.alert_id)}
                  className="text-[#4a6080] hover:text-[#00d4ff] font-mono text-xs transition-colors"
                >
                  Restore
                </button>
                <button
                  onClick={() => removeAlert(alert.alert_id)}
                  className="text-[#4a6080] hover:text-[#ff3c5a] font-mono text-xs transition-colors"
                >
                  Remove
                </button>
              </div>
            ) : (
              <button
                onClick={() => dismissAlert(alert.alert_id)}
                disabled={isInvestigating}
                className={`font-mono text-xs transition-colors ${
                  isInvestigating
                    ? "text-[#1a2535] cursor-not-allowed"
                    : "text-[#4a6080] hover:text-[#ff3c5a]"
                }`}
              >
                Dismiss
              </button>
            )}
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="h-full flex flex-col bg-[#080c12]">
      {/* Header */}
      <div className="p-4 border-b border-[#1a2535] flex-shrink-0">
        <div className="text-[#e2e8f0] font-mono text-sm tracking-widest">
          ALERT FEED
        </div>
        <div className="text-[#4a6080] font-mono text-xs mt-1">
          {activeAlerts.length} active
          {dismissedAlerts.length > 0 && `, ${dismissedAlerts.length} dismissed`}
        </div>
      </div>

      {/* Active alerts */}
      <div className="flex-1 overflow-y-auto">
        {activeAlerts.length === 0 && (
          <div className="p-4 text-[#4a6080] font-mono text-sm">
            No active alerts. Monitoring...
          </div>
        )}
        {activeAlerts.map((alert) => renderAlert(alert, false))}

        {/* Dismissed section */}
        {dismissedAlerts.length > 0 && (
          <div className="border-t border-[#1a2535]">
            <button
              onClick={() => setShowDismissed((v) => !v)}
              className="w-full p-3 flex items-center justify-between text-[#4a6080] hover:text-[#e2e8f0] font-mono text-xs transition-colors"
            >
              <span>DISMISSED ({dismissedAlerts.length})</span>
              <span>{showDismissed ? "▲" : "▼"}</span>
            </button>
            {showDismissed && dismissedAlerts.map((alert) => renderAlert(alert, true))}
          </div>
        )}
      </div>
    </div>
  );
}