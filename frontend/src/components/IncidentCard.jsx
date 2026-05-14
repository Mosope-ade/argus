import SeverityBadge from "./SeverityBadge";

export default function IncidentCard({ incident, onSelect }) {
  return (
    <div
      onClick={() => onSelect(incident)}
      className="border border-[#1a2535] bg-[#0d1117] p-4 cursor-pointer hover:border-[#00d4ff] transition-colors"
    >
      <div className="flex items-center justify-between mb-2">
        <div className="font-mono text-[#e2e8f0] text-sm">
          {incident.incident_id}
        </div>

        <SeverityBadge severity={incident.severity} />
      </div>

      <div className="text-[#e2e8f0] font-mono text-sm mb-2">
        {incident.attack_type}
      </div>

      <div className="text-[#4a6080] font-mono text-xs">
        Systems: {incident.affected_systems.length}
      </div>

      <div className="text-[#4a6080] font-mono text-xs mt-1">
        {incident.timestamp}
      </div>
    </div>
  );
}