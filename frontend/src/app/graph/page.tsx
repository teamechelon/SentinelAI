import { getSentinelDataSource } from "@/data/data-source";

import { GraphVisualization } from "@/components/graph/graph-visualization";
import { GraphFindingsTable } from "@/components/graph/graph-findings-table";

export default async function GraphAnalysisPage() {
  const source = getSentinelDataSource();
  const [overview, graphData, findingsResult] = await Promise.all([
    source.getGraphOverview(),
    source.getGraphData({ maxNodes: 100 }),
    source.getGraphFindings(),
  ]);

  const findings = findingsResult.items.length > 0 ? findingsResult.items : graphData.findings;
  const sharedDevicesCount = findings.filter(f => f.findingType === "SHARED_DEVICE").length || (overview.entityCounts.device ?? 0);
  const sharedIpsCount = findings.filter(f => f.findingType === "SHARED_IP").length || (overview.entityCounts.ip_address ?? 0);

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
        <SummaryCard label="Shared Devices" value={sharedDevicesCount} />
        <SummaryCard label="Shared IPs" value={sharedIpsCount} />
        <SummaryCard label="High-Risk Findings" value={overview.highSeverityFindingCount} accent />
      </div>
      
      {/* Graph Visualization */}
      <div className="panel p-4">
        <div className="mb-3 tech-label">Entity Relationship Graph</div>
        <GraphVisualization nodes={graphData.nodes} edges={graphData.edges} />
      </div>
      
      {/* Findings Table */}
      {findings.length > 0 && (
        <div className="panel p-4">
          <div className="mb-3 tech-label">Graph Findings</div>
          <GraphFindingsTable findings={findings} />
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
