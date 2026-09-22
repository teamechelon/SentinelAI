import { getSentinelDataSource } from "@/data/data-source";

import { GraphVisualization } from "@/components/graph/graph-visualization";
import { GraphFindingsTable } from "@/components/graph/graph-findings-table";

export default async function GraphAnalysisPage() {
  const source = getSentinelDataSource();
  const overview = await source.getGraphOverview();
  
  return (
    <div className="mx-auto max-w-[1600px] space-y-6">
      {/* Header */}
      <div>
        <div className="tech-label">Sentinel / Intelligence</div>
        <h1 className="mt-2 text-[24px] font-bold tracking-[-0.03em]">Graph Analysis</h1>
        <p className="mt-1 text-[12px] text-[var(--text-secondary)]">
          Entity relationships and connection patterns across security events
        </p>
      </div>
      
      {/* Summary Cards */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-3 lg:grid-cols-5">
        <SummaryCard label="Total Entities" value={overview.nodeCount} />
        <SummaryCard label="Relationships" value={overview.edgeCount} />
        <SummaryCard label="Shared Devices" value={overview.findings.filter(f => f.findingType === "SHARED_DEVICE").length} />
        <SummaryCard label="Shared IPs" value={overview.findings.filter(f => f.findingType === "SHARED_IP").length} />
        <SummaryCard label="High-Risk Findings" value={overview.highSeverityFindingCount} accent />
      </div>
      
      {/* Graph Visualization */}
      <div className="panel p-4">
        <div className="mb-3 tech-label">Entity Relationship Graph</div>
        <GraphVisualization nodes={overview.nodes} edges={overview.edges} />
      </div>
      
      {/* Findings Table */}
      {overview.findings.length > 0 && (
        <div className="panel p-4">
          <div className="mb-3 tech-label">Graph Findings</div>
          <GraphFindingsTable findings={overview.findings} />
        </div>
      )}
    </div>
  );
}

function SummaryCard({ label, value, accent }: { label: string; value: number; accent?: boolean }) {
  return (
    <div className="panel p-4">
      <div className="tech-label">{label}</div>
      <div className={`mt-2 text-[28px] font-bold tabular ${accent ? "text-[var(--accent)]" : ""}`}>{value}</div>
    </div>
  );
}
