import { useEffect, useRef } from "react";

export default function AgentLog({ steps = [] }) {
  const bottomRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [steps]);

  const formatPlan = (msg) => {
    return `> plan [${msg.iteration}]: ${msg.action} — ${msg.reasoning}`;
  };

  const formatResult = (msg) => {
    const data = msg.data;
    let summary = "";
    if (data?.summary) {
      summary = data.summary;
    } else if (typeof data === "object") {
      summary = Object.entries(data)
        .map(([k, v]) => `${k}: ${v}`)
        .join(" | ");
    } else {
      summary = String(data);
    }
    return `> result: ${summary}`;
  };

  const isDone = steps.some((s) => s.type === "done");

  return (
    <div className="bg-[#0d1117] border border-[#1a2535] p-4 min-h-[200px] max-h-[400px] overflow-y-auto font-mono text-sm text-[#e2e8f0]">
      {steps.length === 0 && (
        <div className="text-[#4a6080]">
          Waiting for investigation to start...
        </div>
      )}

      {steps.map((step, i) => {
        const key = `${step.type}-${step.iteration ?? step.action ?? step.summary ?? step.message ?? i}`;
        if (step.type === "plan") {
          return (
            <div key={key} className="text-[#00d4ff] mb-1 leading-relaxed">
              {formatPlan(step)}
            </div>
          );
        }
        if (step.type === "result") {
          return (
            <div key={key} className="text-[#00ff9d] mb-1 leading-relaxed">
              {formatResult(step)}
            </div>
          );
        }
        if (step.type === "error") {
          return (
            <div key={key} className="text-[#ff3c5a] mb-1 leading-relaxed">
              {"> error: " + step.message}
            </div>
          );
        }
        return null;
      })}

      {!isDone && steps.length > 0 && (
        <div className="text-[#4a6080] animate-pulse mt-2">▋</div>
      )}

      {isDone && (
        <div className="text-[#00ff9d] mt-2">Investigation complete.</div>
      )}

      <div ref={bottomRef} />
    </div>
  );
}