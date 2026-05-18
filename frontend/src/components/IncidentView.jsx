import { jsPDF } from "jspdf";
import AttackTimeline from "./AttackTimeline";
import AgentLog from "./AgentLog";
import RecommendationsPanel from "./RecommendationsPanel";
import SeverityBadge from "./SeverityBadge";

const sanitize = (str) =>
  (str || "").replace(/→/g, "->").replace(/[^\x00-\x7F]/g, "?");

function exportPDF(incident) {
  const doc = new jsPDF({ unit: "pt", format: "a4" });
  const W = doc.internal.pageSize.getWidth();
  const margin = 48;
  const contentWidth = W - margin * 2;
  let y = margin;

  const colors = {
    cyan:   [0, 212, 255],
    green:  [0, 255, 157],
    red:    [255, 60, 90],
    amber:  [255, 200, 0],
    muted:  [74, 96, 128],
    text:   [226, 232, 240],
    bg:     [8, 12, 18],
    border: [26, 37, 53],
  };

  const severityColor = {
    CRITICAL: colors.red,
    HIGH:     colors.red,
    MEDIUM:   colors.amber,
    LOW:      colors.green,
  };

  const checkPage = (needed = 20) => {
    if (y + needed > doc.internal.pageSize.getHeight() - margin) {
      doc.addPage();
      // Re-fill background on new page
      doc.setFillColor(...colors.bg);
      doc.rect(0, 0, W, doc.internal.pageSize.getHeight(), "F");
      y = margin;
    }
  };

  const sectionHeader = (label) => {
    checkPage(32);
    doc.setFillColor(...colors.border);
    doc.rect(margin, y, contentWidth, 20, "F");
    doc.setFont("helvetica", "bold");
    doc.setFontSize(9);
    doc.setTextColor(...colors.cyan);
    doc.text(label, margin + 8, y + 13);
    y += 28;
  };

  const bodyText = (text, opts = {}) => {
    const size = opts.size || 9;
    doc.setFontSize(size);
    doc.setFont("helvetica", opts.bold ? "bold" : "normal");
    doc.setTextColor(...(opts.color || colors.text));
    const lines = doc.splitTextToSize(sanitize(text), contentWidth - (opts.indent || 0));
    lines.forEach((line) => {
      checkPage(size + 4);
      doc.text(line, margin + (opts.indent || 0), y);
      y += size + 4;
    });
    if (opts.gap) y += opts.gap;
  };

  // ── Dark background (page 1) ─────────────────────────────────────────────
  doc.setFillColor(...colors.bg);
  doc.rect(0, 0, W, doc.internal.pageSize.getHeight(), "F");

  // ── Header bar ───────────────────────────────────────────────────────────
  doc.setFillColor(...colors.border);
  doc.rect(0, 0, W, 70, "F");

  doc.setFont("helvetica", "bold");
  doc.setFontSize(22);
  doc.setTextColor(...colors.cyan);
  doc.text("ARGUS", margin, 36);

  doc.setFont("helvetica", "normal");
  doc.setFontSize(9);
  doc.setTextColor(...colors.muted);
  doc.text("Agentic Incident Responder — Incident Report", margin, 52);

  // Severity badge (top right)
  const sev = incident.severity || "UNKNOWN";
  const sevCol = severityColor[sev] || colors.muted;
  doc.setFillColor(...sevCol);
  doc.roundedRect(W - margin - 70, 18, 70, 22, 3, 3, "F");
  doc.setFont("helvetica", "bold");
  doc.setFontSize(10);
  doc.setTextColor(8, 12, 18);
  doc.text(sev, W - margin - 35, 33, { align: "center" });

  y = 90;

  // ── Incident metadata ────────────────────────────────────────────────────
  sectionHeader("INCIDENT DETAILS");

  const meta = [
    ["Incident ID",       incident.incident_id],
    ["Alert ID",          incident.alert_id],
    ["Timestamp",         incident.timestamp],
    ["Attack Type",       sanitize(incident.attack_type)],
    ["Affected Systems",  (incident.affected_systems || []).join(", ")],
    ["Compromised Accts", (incident.compromised_accounts || []).join(", ") || "None"],
  ];

  meta.forEach(([label, value]) => {
    checkPage(16);
    doc.setFontSize(9);
    doc.setFont("helvetica", "bold");
    doc.setTextColor(...colors.muted);
    doc.text(`${label}:`, margin, y);
    doc.setFont("helvetica", "normal");
    doc.setTextColor(...colors.text);
    const lines = doc.splitTextToSize(sanitize(String(value || "—")), contentWidth - 130);
    doc.text(lines, margin + 130, y);
    y += Math.max(lines.length * 13, 14);
  });

  y += 8;

  // ── Summary ──────────────────────────────────────────────────────────────
  sectionHeader("SUMMARY");
  bodyText(incident.summary || "No summary available.", { gap: 8 });

  // ── Attack timeline ──────────────────────────────────────────────────────
  if (incident.timeline?.length > 0) {
    sectionHeader("ATTACK CHAIN TIMELINE");
    incident.timeline.forEach((event) => {
      checkPage(48);
      doc.setFontSize(8);
      doc.setFont("helvetica", "bold");
      doc.setTextColor(...colors.cyan);
      doc.text(sanitize(event.time || "—"), margin, y);
      doc.setFont("helvetica", "bold");
      doc.setTextColor(...colors.text);
      const evLines = doc.splitTextToSize(sanitize(event.event || ""), contentWidth - 60);
      doc.text(evLines, margin + 55, y);
      y += evLines.length * 12 + 2;
      if (event.mitre_technique) {
        doc.setFont("helvetica", "normal");
        doc.setFontSize(7.5);
        doc.setTextColor(...colors.muted);
        doc.text(
          sanitize(`${event.mitre_technique}  .  ${event.mitre_tactic || ""}`),
          margin + 55, y,
        );
        y += 11;
      }
      if (event.raw_log) {
        doc.setFont("courier", "normal");
        doc.setFontSize(7);
        doc.setTextColor(...colors.muted);
        const raw = sanitize(String(event.raw_log).slice(0, 120) + (event.raw_log.length > 120 ? "..." : ""));
        const rawLines = doc.splitTextToSize(raw, contentWidth - 60);
        rawLines.forEach((l) => {
          checkPage(10);
          doc.text(l, margin + 55, y);
          y += 9;
        });
      }
      y += 6;
    });
    y += 4;
  }

  // ── MITRE mapping ────────────────────────────────────────────────────────
  if (incident.mitre_mapping?.length > 0) {
    sectionHeader("MITRE ATT&CK MAPPING");
    incident.mitre_mapping.forEach((m) => {
      checkPage(36);
      doc.setFontSize(9);
      doc.setFont("helvetica", "bold");
      doc.setTextColor(...colors.cyan);
      doc.text(sanitize(m.technique_id), margin, y);
      doc.setFont("helvetica", "normal");
      doc.setTextColor(...colors.text);
      doc.text(sanitize(m.technique_name), margin + 65, y);
      y += 13;
      doc.setFontSize(8);
      doc.setTextColor(...colors.muted);
      doc.text(sanitize(`Tactic: ${m.tactic}`), margin + 65, y);
      y += 16;
    });
    y += 4;
  }

  // ── IOC matches ──────────────────────────────────────────────────────────
  if (incident.ioc_matches?.length > 0) {
    sectionHeader("IOC MATCHES");
    incident.ioc_matches.forEach((ioc) => {
      checkPage(36);
      doc.setFontSize(9);
      doc.setFont("helvetica", "bold");
      doc.setTextColor(...colors.red);
      doc.text(sanitize(ioc.ioc), margin, y);
      doc.setFont("helvetica", "normal");
      doc.setTextColor(...colors.text);
      doc.text(sanitize(`  ${ioc.threat}`), margin + 110, y);
      y += 13;
      doc.setFontSize(8);
      doc.setTextColor(...colors.muted);
      doc.text(
        sanitize(`Confidence: ${ioc.confidence}  .  Feeds: ${(ioc.feeds || []).join(", ")}`),
        margin, y,
      );
      y += 16;
    });
    y += 4;
  }

  // ── Recommendations ──────────────────────────────────────────────────────
  if (incident.recommendations?.length > 0) {
    sectionHeader("RECOMMENDATIONS");
    incident.recommendations.forEach((r, i) => {
      checkPage(20);
      doc.setFontSize(9);
      doc.setFont("helvetica", "bold");
      doc.setTextColor(...colors.green);
      doc.text(`${i + 1}.`, margin, y);
      doc.setFont("helvetica", "normal");
      doc.setTextColor(...colors.text);
      const lines = doc.splitTextToSize(sanitize(r), contentWidth - 20);
      lines.forEach((line) => {
        checkPage(13);
        doc.text(line, margin + 20, y);
        y += 13;
      });
      y += 3;
    });
    y += 4;
  }

  // ── Agent metadata ───────────────────────────────────────────────────────
  sectionHeader("AGENT METADATA");
  bodyText(`Iterations: ${incident.agent_iterations ?? "—"}`, { color: colors.muted });
  bodyText(
    `Actions taken: ${(incident.actions_taken || []).join(" -> ")}`,
    { color: colors.muted, gap: 4 },
  );

  // ── Footer (all pages) ───────────────────────────────────────────────────
  const pageCount = doc.getNumberOfPages();
  for (let p = 1; p <= pageCount; p++) {
    doc.setPage(p);
    const ph = doc.internal.pageSize.getHeight();
    doc.setFillColor(...colors.border);
    doc.rect(0, ph - 28, W, 28, "F");
    doc.setFontSize(7.5);
    doc.setFont("helvetica", "normal");
    doc.setTextColor(...colors.muted);
    doc.text("Generated by Argus — Agentic Incident Responder", margin, ph - 10);
    doc.text(`Page ${p} of ${pageCount}`, W - margin, ph - 10, { align: "right" });
  }

  doc.save(`${incident.incident_id}.pdf`);
}

export default function IncidentView({ incident, agentSteps = [] }) {
  if (!incident) return null;

  return (
    <div className="h-full overflow-y-auto">
      {/* HEADER */}
      <div className="border-b border-[#1a2535] p-6">
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-4 flex-wrap">
            <div className="text-2xl font-bold text-[#e2e8f0]">
              {incident.incident_id}
            </div>
            <SeverityBadge severity={incident.severity} />
            <div className="text-[#e2e8f0] font-mono">
              {incident.attack_type}
            </div>
          </div>

          {/* Export button */}
          <button
            onClick={() => exportPDF(incident)}
            className="flex items-center gap-2 px-4 py-2 border border-[#1a2535] text-[#00d4ff] font-mono text-sm hover:border-[#00d4ff] hover:bg-[#00d4ff10] transition-colors"
          >
            <svg
              className="w-4 h-4"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={1.5}
                d="M12 4v12m0 0l-4-4m4 4l4-4M4 20h16"
              />
            </svg>
            Export PDF
          </button>
        </div>

        <div className="mt-3 text-sm text-[#4a6080] font-mono">
          {incident.timestamp}
        </div>
        <div className="mt-2 text-sm text-[#4a6080] font-mono">
          Affected Systems: {incident.affected_systems?.join(", ")}
        </div>
      </div>

      {/* SUMMARY */}
      {incident.summary && (
        <div className="px-6 pt-4">
          <div className="border border-[#1a2535] bg-[#0d1117] p-4">
            <div className="text-[#e2e8f0] font-mono text-sm mb-2 tracking-widest">
              SUMMARY
            </div>
            <div className="text-[#4a6080] font-mono text-sm leading-relaxed">
              {incident.summary}
            </div>
          </div>
        </div>
      )}

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
            compromised_accounts={incident.compromised_accounts}
            incident_id={incident.incident_id}
          />

          <div className="border border-[#1a2535] bg-[#0d1117] p-4">
            <div className="text-[#e2e8f0] font-mono mb-4">MITRE MAPPING</div>
            <div className="space-y-2">
              {incident.mitre_mapping?.map((m, i) => (
                <div key={i} className="border border-[#1a2535] p-3">
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