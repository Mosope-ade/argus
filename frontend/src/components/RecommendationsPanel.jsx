import { useState } from "react";

export default function RecommendationsPanel({
  recommendations = [],
  ioc_matches = [],
  compromised_accounts = [],
}) {
  const [checked, setChecked] = useState({});

  const toggle = (i) => {
    setChecked((prev) => ({ ...prev, [i]: !prev[i] }));
  };

  return (
    <div className="bg-[#0d1117] border border-[#1a2535] p-4 font-mono text-sm text-[#e2e8f0]">
      <div className="mb-3 text-[#e2e8f0]">RECOMMENDATIONS</div>

      {recommendations.map((r, i) => (
        <div key={i} className="flex items-start gap-2 mb-2">
          <input
            type="checkbox"
            checked={!!checked[i]}
            onChange={() => toggle(i)}
          />
          <span>{r}</span>
        </div>
      ))}

      {ioc_matches.length > 0 && (
        <div className="mt-4 border-t border-[#1a2535] pt-2">
          <div className="text-[#ff3c5a] mb-2">IOC MATCHES</div>

          {ioc_matches.map((ioc, i) => (
            <div key={i} className="text-[#ff3c5a] text-xs mb-1">
              {ioc.ioc} — {ioc.threat} ({ioc.confidence})
            </div>
          ))}
        </div>
      )}

      {compromised_accounts.length > 0 && (
        <div className="mt-4 text-[#ffc800] border-t border-[#1a2535] pt-2">
          Compromised: {compromised_accounts.join(", ")}
        </div>
      )}
    </div>
  );
}