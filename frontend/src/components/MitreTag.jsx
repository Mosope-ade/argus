export default function MitreTag({ techniqueId, techniqueName }) {
    return (
      <span className="border border-[#00d4ff] text-[#00d4ff] px-2 py-1 text-xs font-mono">
        {techniqueId} — {techniqueName}
      </span>
    );
  }