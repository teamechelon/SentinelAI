"use client";

import { useMemo, useRef, useState, useCallback } from "react";
import type * as echarts from "echarts/core";
import type { GraphOverview, GraphData, GraphFinding, GraphNode } from "@/domain/sentinel";
import { GraphSummaryCards } from "./graph-summary-cards";
import { GraphToolbar } from "./graph-toolbar";
import { GraphVisualization } from "./graph-visualization";
import { GraphDetailPanel } from "./graph-detail-panel";
import { GraphFindingsTable } from "./graph-findings-table";
import { GraphMethodology } from "./graph-methodology";
import { getNodeRiskLevel } from "./graph-types";

interface GraphDashboardClientProps {
  overview: GraphOverview;
  initialGraphData: GraphData;
  initialFindings: GraphFinding[];
}

export function GraphDashboardClient({
  overview,
  initialGraphData,
  initialFindings,
}: GraphDashboardClientProps) {
  // Chart instance ref
  const chartRef = useRef<echarts.ECharts | null>(null);

  // Interactive selection state
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<GraphFinding | null>(null);

  // Filters & Controls
  const [searchQuery, setSearchQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [riskFilter, setRiskFilter] = useState("all");
  const [rearrangeEnabled, setRearrangeEnabled] = useState(false);
  const [showAllLabels, setShowAllLabels] = useState(false);

  // Filtered nodes calculation (memoized for high performance)
  const filteredNodes = useMemo(() => {
    return initialGraphData.nodes.filter((node) => {
      // 1. Type Filter
      if (typeFilter !== "all" && node.nodeType !== typeFilter) {
        return false;
      }

      // 2. Risk Filter
      if (riskFilter !== "all") {
        const risk = getNodeRiskLevel(node);
        if (risk !== riskFilter) {
          return false;
        }
      }

      // 3. Search Query Filter
      if (searchQuery.trim().length > 0) {
        const q = searchQuery.toLowerCase();
        const matchesLabel = node.label.toLowerCase().includes(q);
        const matchesId = node.nodeId.toLowerCase().includes(q);
        const matchesDept = (node.metadata.department as string)?.toLowerCase().includes(q);
        const matchesScenario = (node.metadata.scenario as string)?.toLowerCase().includes(q);
        if (!matchesLabel && !matchesId && !matchesDept && !matchesScenario) {
          return false;
        }
      }

      return true;
    });
  }, [initialGraphData.nodes, typeFilter, riskFilter, searchQuery]);

  // Node ID set for valid edge lookup
  const nodeIdsSet = useMemo(() => new Set(filteredNodes.map((n) => n.nodeId)), [filteredNodes]);

  // Edges filtered strictly to present nodes (guarantees Requirement 6: no dangling edges)
  const filteredEdges = useMemo(() => {
    return initialGraphData.edges.filter(
      (e) => nodeIdsSet.has(e.sourceId) && nodeIdsSet.has(e.targetId)
    );
  }, [initialGraphData.edges, nodeIdsSet]);

  // Search Results for autocomplete dropdown
  const searchResults = useMemo(() => {
    if (searchQuery.trim().length <= 1) return [];
    const q = searchQuery.toLowerCase();
    return initialGraphData.nodes.filter(
      (n) =>
        n.label.toLowerCase().includes(q) ||
        n.nodeId.toLowerCase().includes(q) ||
        (n.metadata.department as string)?.toLowerCase().includes(q)
    );
  }, [searchQuery, initialGraphData.nodes]);

  // Highlighted entity IDs (from selected finding)
  const highlightedEntityIds = useMemo(() => {
    if (!selectedFinding) return [];
    return [
      ...selectedFinding.entities,
      ...selectedFinding.supportingEvents.map((eid) => `event:${eid}`),
    ];
  }, [selectedFinding]);

  // Handlers
  const handleSelectNode = useCallback((node: GraphNode | null) => {
    setSelectedNode(node);
    if (node) {
      setSelectedFinding(null);
    }
  }, []);

  const handleSelectFinding = useCallback(
    (finding: GraphFinding) => {
      if (selectedFinding === finding) {
        setSelectedFinding(null);
        return;
      }
      setSelectedFinding(finding);

      // Find first matching node in graph to show in inspector
      const firstEntityId = finding.entities[0];
      const match = initialGraphData.nodes.find(
        (n) => n.nodeId === firstEntityId || n.label === firstEntityId
      );
      if (match) {
        setSelectedNode(match);
      }
    },
    [selectedFinding, initialGraphData.nodes]
  );

  const handleSelectRelatedNode = useCallback(
    (nodeId: string) => {
      const match = initialGraphData.nodes.find((n) => n.nodeId === nodeId);
      if (match) {
        setSelectedNode(match);
      }
    },
    [initialGraphData.nodes]
  );

  const handleFocusNode = useCallback((node: GraphNode) => {
    setSelectedNode(node);
    // Programmatically center or restore chart view
    if (chartRef.current) {
      chartRef.current.dispatchAction({
        type: "restore",
      });
    }
  }, []);

  const handleFitView = useCallback(() => {
    if (chartRef.current) {
      chartRef.current.dispatchAction({
        type: "restore",
      });
    }
  }, []);

  const handleResetView = useCallback(() => {
    if (chartRef.current) {
      chartRef.current.dispatchAction({
        type: "restore",
      });
    }
    setSelectedNode(null);
    setSelectedFinding(null);
    setTypeFilter("all");
    setRiskFilter("all");
    setSearchQuery("");
  }, []);

  const handleClearFilters = useCallback(() => {
    setTypeFilter("all");
    setRiskFilter("all");
    setSearchQuery("");
  }, []);

  return (
    <div className="space-y-6">
      {/* 1. Formal Summary Cards */}
      <GraphSummaryCards overview={overview} findings={initialFindings} />

      {/* 2. Interactive Graph Toolbar */}
      <GraphToolbar
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
        typeFilter={typeFilter}
        onTypeFilterChange={setTypeFilter}
        riskFilter={riskFilter}
        onRiskFilterChange={setRiskFilter}
        rearrangeEnabled={rearrangeEnabled}
        onToggleRearrange={() => setRearrangeEnabled(!rearrangeEnabled)}
        showAllLabels={showAllLabels}
        onToggleLabels={() => setShowAllLabels(!showAllLabels)}
        onFitView={handleFitView}
        onResetView={handleResetView}
        totalFilteredNodes={filteredNodes.length}
        totalNodes={initialGraphData.nodes.length}
        searchResults={searchResults}
        onSelectSearchResult={(node) => {
          setSelectedNode(node);
          setSearchQuery("");
        }}
        onClearFilters={handleClearFilters}
      />

      {/* 3. Main Workspace: Interactive Canvas + Side Inspector (Requirement 35) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        {/* Graph Canvas */}
        <div className={selectedNode ? "lg:col-span-8 xl:col-span-9 transition-all" : "lg:col-span-12 transition-all"}>
          <div className="panel p-4 bg-[var(--surface)] border border-[var(--border)] rounded-lg shadow-xs space-y-3">
            <div className="flex items-center justify-between border-b border-[var(--border)] pb-2.5">
              <div>
                <span className="tech-label text-[10px] tracking-wider text-[var(--accent)] font-semibold">
                  Sentinel / Knowledge Graph
                </span>
                <h2 className="text-sm font-bold text-[var(--foreground)] mt-0.5">
                  Entity Relationship Security Topology
                </h2>
              </div>
              <div className="text-[11px] text-[var(--text-muted)] flex items-center gap-2">
                <span>Click any node to inspect context</span>
                {selectedFinding && (
                  <span className="px-2 py-0.5 rounded bg-orange-50 text-orange-700 border border-orange-200 font-semibold text-[10.5px]">
                    Highlighting: {selectedFinding.findingType}
                  </span>
                )}
              </div>
            </div>

            <GraphVisualization
              nodes={filteredNodes}
              edges={filteredEdges}
              selectedNode={selectedNode}
              onSelectNode={handleSelectNode}
              highlightedEntityIds={highlightedEntityIds}
              rearrangeEnabled={rearrangeEnabled}
              showAllLabels={showAllLabels}
              chartRef={chartRef}
            />
          </div>
        </div>

        {/* Side Inspector Detail Panel */}
        {selectedNode && (
          <div className="lg:col-span-4 xl:col-span-3 sticky top-4">
            <GraphDetailPanel
              node={selectedNode}
              edges={initialGraphData.edges}
              findings={initialFindings}
              onClose={() => setSelectedNode(null)}
              onSelectRelatedNode={handleSelectRelatedNode}
              onFocusNode={handleFocusNode}
            />
          </div>
        )}
      </div>

      {/* 4. Graph Findings Table */}
      {initialFindings.length > 0 && (
        <div className="panel p-4 bg-[var(--surface)] border border-[var(--border)] rounded-lg shadow-xs space-y-3">
          <div className="flex items-center justify-between border-b border-[var(--border)] pb-2.5">
            <div>
              <span className="tech-label text-[10px] tracking-wider text-amber-700 font-semibold">
                Correlated Intelligence
              </span>
              <h2 className="text-sm font-bold text-[var(--foreground)] mt-0.5">
                Active Graph Security Findings
              </h2>
            </div>
            <div className="text-[11px] text-[var(--text-muted)]">
              Click <strong className="text-[var(--accent)]">Highlight</strong> to trace entities in the graph
            </div>
          </div>

          <GraphFindingsTable
            findings={initialFindings}
            selectedFinding={selectedFinding}
            onSelectFinding={handleSelectFinding}
          />
        </div>
      )}

      {/* 5. Methodology, Parameter Reference, and False-Positive Safeguards */}
      <GraphMethodology />
    </div>
  );
}
