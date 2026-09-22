import { getSentinelDataSource } from "@/data/data-source";
import { GraphDashboardClient } from "@/components/graph/graph-dashboard-client";

export const dynamic = "force-dynamic";

export default async function GraphAnalysisPage() {
  const source = getSentinelDataSource();
  const [overview, graphData, findingsResult] = await Promise.all([
    source.getGraphOverview(),
    source.getGraphData({ maxNodes: 120 }),
    source.getGraphFindings(),
  ]);

  const findings = findingsResult.items.length > 0 ? findingsResult.items : graphData.findings;

  return (
    <div className="mx-auto max-w-[1600px] space-y-6">
      {/* Header */}
      <div>
        <div className="tech-label">Sentinel / Intelligence</div>
        <h1 className="mt-2 text-[24px] font-bold tracking-[-0.03em]">Graph Analysis</h1>
        <p className="mt-1 text-[12px] text-[var(--text-secondary)]">
          Entity relationships, risk topology, and multi-user correlation patterns across security events
        </p>
      </div>

      {/* Main Interactive Graph Client */}
      <GraphDashboardClient
        overview={overview}
        initialGraphData={graphData}
        initialFindings={findings}
      />
    </div>
  );
}
