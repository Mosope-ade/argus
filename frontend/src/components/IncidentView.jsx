import AttackTimeline from "./AttackTimeline";
import AgentLog from "./AgentLog";
import RecommendationsPanel from "./RecommendationsPanel";
import SeverityBadge from "./SeverityBadge";

export default function IncidentView({
  incident,
  agentSteps = [],
}) {
  if (!incident) return null;

  return (
    <div className="h-full overflow-y-auto">
      {/* HEADER */}
      <div className="border-b border-[#1a2535] p-6">
        <div className="flex items-center gap-4 flex-wrap">
          <div className="text-2xl font-bold text-[#e2e8f0]">
            {incident.incident_id}
          </div>

          <SeverityBadge severity={incident.severity} />

          <div className="text-[#e2e8f0] font-mono">
            {incident.attack_type}
          </div>
        </div>

        <div className="mt-3 text-sm text-[#4a6080] font-mono">
          {incident.timestamp}
        </div>

        <div className="mt-2 text-sm text-[#4a6080] font-mono">
          Affected Systems:{" "}
          {incident.affected_systems.join(", ")}
        </div>
      </div>

      {/* CONTENT */}
      <div className="grid grid-cols-2 gap-4 p-6">
        {/* LEFT */}
        <div className="space-y-4">
          <AttackTimeline timeline={incident.timeline} />

          <div>
            <div className="text-[#e2e8f0] font-mono mb-2">
              AGENT REASONING LOG
            </div>

            <AgentLog steps={agentSteps} />
          </div>
        </div>

        {/* RIGHT */}
        <div className="space-y-4">
          <RecommendationsPanel
            recommendations={incident.recommendations}
            ioc_matches={incident.ioc_matches}
            compromised_accounts={
              incident.compromised_accounts
            }
          />

          <div className="border border-[#1a2535] bg-[#0d1117] p-4">
            <div className="text-[#e2e8f0] font-mono mb-4">
              MITRE MAPPING
            </div>

            <div className="space-y-2">
              {incident.mitre_mapping.map((m, i) => (
                <div
                  key={i}
                  className="border border-[#1a2535] p-3"
                >
                  <div className="text-[#00d4ff] font-mono text-sm">
                    {m.technique_id}
                  </div>

                  <div className="text-[#e2e8f0] font-mono text-sm mt-1">
                    {m.technique_name}
                  </div>

                  <div className="text-[#4a6080] font-mono text-xs mt-1">
                    {m.tactic}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}