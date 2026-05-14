export default function SeverityBadge({ severity }) {
    const colorMap = {
      CRITICAL: "#ff3c5a",
      HIGH: "#ffc800",
      MEDIUM: "#00d4ff",
      LOW: "#4a6080",
    };
  
    return (
      <span
        className="px-2 py-1 text-xs font-mono text-[#080c12]"
        style={{ backgroundColor: colorMap[severity] }}
      >
        {severity}
      </span>
    );
  }