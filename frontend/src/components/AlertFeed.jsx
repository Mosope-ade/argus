import { useEffect, useState } from "react";
import { api } from "../api/argus";

function relativeTime(timestamp) {
  const diff =
    Math.floor(
      (Date.now() - new Date(timestamp)) / 1000
    );

  if (diff < 60) return `${diff}s ago`;

  if (diff < 3600)
    return `${Math.floor(diff / 60)}m ago`;

  return `${Math.floor(diff / 3600)}h ago`;
}

export default function AlertFeed({
  wsMessages = [],
}) {
  const [alerts, setAlerts] = useState([]);
  const [investigating, setInvestigating] =
    useState({});

  useEffect(() => {
    const loadAlerts = async () => {
      try {
        const res = await api.getAlerts();
        const data = await res.json();

        setAlerts(data.alerts || []);
      } catch (err) {
        console.error(err);
      }
    };

    loadAlerts();
  }, []);

  useEffect(() => {
    const latest =
      wsMessages[wsMessages.length - 1];

    if (latest?.type === "new_alert") {
      setAlerts((prev) => [
        latest.alert,
        ...prev,
      ]);
    }
  }, [wsMessages]);

  const handleInvestigate = (id) => {
    setInvestigating((prev) => ({
      ...prev,
      [id]: true,
    }));
  };

  return (
    <div className="h-full overflow-y-auto bg-[#080c12]">
      <div className="p-4 border-b border-[#1a2535]">
        <div className="text-[#e2e8f0] font-mono">
          ALERT FEED
        </div>
      </div>

      <div>
        {alerts.map((alert, index) => (
          <div
            key={alert.alert_id}
            className={`p-4 border-b border-[#1a2535] transition-all ${
              index === 0
                ? "bg-[#0d1117]"
                : ""
            }`}
          >
            <div className="flex items-start justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-[#ff3c5a]">
                    ●
                  </span>

                  <span className="text-[#e2e8f0] font-mono text-sm">
                    {alert.search_name}
                  </span>
                </div>

                <div className="mt-2 text-[#4a6080] font-mono text-xs">
                  SRC: {alert.src_ip}
                </div>

                <div className="text-[#4a6080] font-mono text-xs">
                  HOST: {alert.host}
                </div>

                <div className="mt-2 text-[#4a6080] font-mono text-xs">
                  {relativeTime(alert.timestamp)}
                </div>
              </div>

              <button
                onClick={() =>
                  handleInvestigate(
                    alert.alert_id
                  )
                }
                className={`px-3 py-1 border text-xs font-mono transition-colors ${
                  investigating[alert.alert_id]
                    ? "border-[#00ff9d] text-[#00ff9d]"
                    : "border-[#1a2535] text-[#00d4ff] hover:border-[#00d4ff]"
                }`}
              >
                {investigating[alert.alert_id]
                  ? "Investigating..."
                  : "Investigate"}
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}