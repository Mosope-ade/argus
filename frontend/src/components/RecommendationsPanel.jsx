import { useState, useEffect } from "react";

export default function RecommendationsPanel({
  recommendations = [],
  ioc_matches = [],
  compromised_accounts = [],
  incident_id = "",
}) {
  const [checked, setChecked] = useState({});

  // Reset checkboxes whenever the incident changes
  useEffect(() => {
    setChecked({});
  }, [incident_id]);

  const toggle = (i) =>
    setChecked((prev) => ({ ...prev, [i]: !prev[i] }));

  return (
    <div className="bg-[#0d1117] border border-[#1a2535] p-4 font-mono text-sm text-[#e2e8f0]">
      <div className="mb-3 text-[#e2e8f0] tracking-widest">RECOMMENDATIONS</div>

      {recommendations.map((r, i) => (
        <div
          key={i}
          onClick={() => toggle(i)}
          className="flex items-start gap-3 mb-3 cursor-pointer group"
        >
          <div className={`mt-0.5 flex-shrink-0 w-4 h-4 border transition-colors ${
            checked[i]
              ? "border-[#00ff9d] bg-[#00ff9d15]"
              : "border-[#1a2535] group-hover:border-[#00d4ff]"
          }`}>
            {checked[i] && (
              <svg viewBox="0 0 16 16" className="w-full h-full text-[#00ff9d]">
                <polyline
                  points="3,8 6,12 13,4"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                />
              </svg>
            )}
          </div>
          <span className={`transition-colors ${
            checked[i] ? "text-[#4a6080] line-through" : "text-[#e2e8f0]"
          }`}>
            {r}
          </span>
        </div>
      ))}

      {ioc_matches.length > 0 && (
        <div className="mt-4 border-t border-[#1a2535] pt-3">
          <div className="text-[#ff3c5a] mb-2 tracking-widest">IOC MATCHES</div>
          {ioc_matches.map((ioc, i) => (
            <div key={i} className="text-[#ff3c5a] text-xs mb-2">
              <span className="text-[#e2e8f0]">{ioc.ioc}</span>
              {" — "}
              {ioc.threat}
              <span className="ml-2 text-[#4a6080]">({ioc.confidence})</span>
            </div>
          ))}
        </div>
      )}

      {compromised_accounts.length > 0 && (
        <div className="mt-4 border-t border-[#1a2535] pt-3 text-[#ffc800]">
          Compromised: {compromised_accounts.join(", ")}
        </div>
      )}
    </div>
  );
}