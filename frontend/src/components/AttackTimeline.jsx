import { useState } from "react";

import {
  ResponsiveContainer,
  ScatterChart,
  Scatter,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Cell,
} from "recharts";

const tacticColors = {
  "Credential Access": "#ff3c5a",
  Discovery: "#ffc800",
  "Lateral Movement": "#00d4ff",
  "Command and Control": "#ff3c5a",
  "Defense Evasion": "#7c6aff",
};

export default function AttackTimeline({
  timeline = [],
}) {
  const [selectedEvent, setSelectedEvent] =
    useState(null);

  const data = timeline.map((event, index) => ({
    ...event,
    x: index + 1,
    y: 1,
  }));

  return (
    <div className="border border-[#1a2535] bg-[#0d1117] p-4">
      <div className="text-[#e2e8f0] font-mono mb-4">
        ATTACK CHAIN TIMELINE
      </div>

      <div className="w-full h-[240px]">
        <ResponsiveContainer width="100%" height="100%">
          <ScatterChart margin={{ top: 20, right: 20, bottom: 20, left: 20 }}>
            <CartesianGrid
              stroke="#1a2535"
              vertical={false}
            />

            <XAxis
              dataKey="time"
              type="category"
              stroke="#4a6080"
              tick={{ fill: "#4a6080", fontSize: 12 }}
            />

            <YAxis hide type="number" dataKey="y" />

            <Tooltip
              cursor={{ stroke: "#00d4ff" }}
              contentStyle={{
                background: "#0d1117",
                border: "1px solid #1a2535",
                color: "#e2e8f0",
              }}
            />

            <Scatter
              data={data}
              onClick={(e) => setSelectedEvent(e)}
            >
              {data.map((entry, index) => (
                <Cell
                  key={index}
                  fill={
                    tacticColors[
                      entry.mitre_tactic
                    ] || "#00d4ff"
                  }
                />
              ))}
            </Scatter>
          </ScatterChart>
        </ResponsiveContainer>
      </div>

      {selectedEvent && (
        <div className="mt-4 border-t border-[#1a2535] pt-4">
          <div className="text-[#00d4ff] font-mono text-sm mb-2">
            {selectedEvent.event}
          </div>

          <div className="text-[#4a6080] font-mono text-xs mb-2 break-all">
            {selectedEvent.raw_log}
          </div>

          <div className="text-[#ffc800] font-mono text-xs">
            {selectedEvent.mitre_technique}
          </div>
        </div>
      )}
    </div>
  );
}