"use client";

import { Search, Filter, RotateCcw, Maximize2, Tag, Move, X } from "lucide-react";
import type { GraphNode } from "@/domain/sentinel";

interface GraphToolbarProps {
  searchQuery: string;
  onSearchChange: (q: string) => void;
  typeFilter: string;
  onTypeFilterChange: (type: string) => void;
  riskFilter: string;
  onRiskFilterChange: (risk: string) => void;
  rearrangeEnabled: boolean;
  onToggleRearrange: () => void;
  showAllLabels: boolean;
  onToggleLabels: () => void;
  onFitView: () => void;
  onResetView: () => void;
  totalFilteredNodes: number;
  totalNodes: number;
  searchResults: GraphNode[];
  onSelectSearchResult: (node: GraphNode) => void;
  onClearFilters: () => void;
}

export function GraphToolbar({
  searchQuery,
  onSearchChange,
  typeFilter,
  onTypeFilterChange,
  riskFilter,
  onRiskFilterChange,
  rearrangeEnabled,
  onToggleRearrange,
  showAllLabels,
  onToggleLabels,
  onFitView,
  onResetView,
  totalFilteredNodes,
  totalNodes,
  searchResults,
  onSelectSearchResult,
  onClearFilters,
}: GraphToolbarProps) {
  const hasActiveFilters = searchQuery !== "" || typeFilter !== "all" || riskFilter !== "all";

  return (
    <div className="bg-[var(--surface)] border border-[var(--border)] rounded-lg p-3 shadow-xs space-y-2.5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        {/* Search Input with Autocomplete dropdown */}
        <div className="relative flex-1 min-w-[240px] max-w-[360px]">
          <div className="relative flex items-center">
            <Search className="absolute left-2.5 size-3.5 text-[var(--text-muted)] pointer-events-none" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => onSearchChange(e.target.value)}
              placeholder="Search employee, event, device, IP, file..."
              className="w-full pl-8 pr-7 py-1.5 text-xs bg-[var(--surface-elevated)] border border-[var(--border)] rounded-md focus:outline-none focus:border-[var(--accent)] transition-colors placeholder:text-[var(--text-muted)]"
            />
            {searchQuery && (
              <button
                type="button"
                onClick={() => onSearchChange("")}
                className="absolute right-2 text-[var(--text-muted)] hover:text-[var(--foreground)]"
              >
                <X className="size-3" />
              </button>
            )}
          </div>

          {/* Quick Search Results Dropdown */}
          {searchQuery.trim().length > 1 && searchResults.length > 0 && (
            <div className="absolute left-0 right-0 top-full mt-1.5 z-40 max-h-56 overflow-y-auto bg-[var(--surface)] border border-[var(--border-strong)] rounded-md shadow-lg divide-y divide-[var(--border)] text-xs">
              {searchResults.slice(0, 8).map((node) => (
                <button
                  key={node.nodeId}
                  type="button"
                  onClick={() => {
                    onSelectSearchResult(node);
                    onSearchChange("");
                  }}
                  className="w-full px-3 py-2 text-left hover:bg-[var(--surface-hover)] flex items-center justify-between transition-colors"
                >
                  <span className="font-medium truncate mr-2">{node.label}</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--surface-elevated)] text-[var(--text-secondary)] capitalize shrink-0">
                    {node.nodeType.replace("_", " ")}
                  </span>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Entity Type Filter */}
          <div className="flex items-center text-xs space-x-1">
            <span className="text-[var(--text-secondary)] font-medium text-[11px] hidden sm:inline">Type:</span>
            <select
              value={typeFilter}
              onChange={(e) => onTypeFilterChange(e.target.value)}
              className="px-2 py-1 text-xs bg-[var(--surface-elevated)] border border-[var(--border)] rounded-md focus:outline-none focus:border-[var(--accent)]"
            >
              <option value="all">All Entity Types</option>
              <option value="employee">Employees</option>
              <option value="event">Security Events</option>
              <option value="device">Devices</option>
              <option value="ip_address">IP Addresses</option>
              <option value="location">Locations</option>
              <option value="file">Files</option>
              <option value="department">Departments</option>
              <option value="attack_run">Attack Runs</option>
            </select>
          </div>

          {/* Risk Filter */}
          <div className="flex items-center text-xs space-x-1">
            <span className="text-[var(--text-secondary)] font-medium text-[11px] hidden sm:inline">Risk:</span>
            <select
              value={riskFilter}
              onChange={(e) => onRiskFilterChange(e.target.value)}
              className="px-2 py-1 text-xs bg-[var(--surface-elevated)] border border-[var(--border)] rounded-md focus:outline-none focus:border-[var(--accent)]"
            >
              <option value="all">All Risk Levels</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>

          {hasActiveFilters && (
            <button
              type="button"
              onClick={onClearFilters}
              className="px-2 py-1 text-[11px] font-medium text-[var(--text-muted)] hover:text-[var(--critical)] border border-[var(--border)] rounded-md hover:bg-red-50 transition-colors"
            >
              Reset Filters
            </button>
          )}
        </div>

        {/* View Controls */}
        <div className="flex items-center gap-1.5 border-l border-[var(--border)] pl-2 sm:pl-3 ml-auto">
          {/* Label Visibility Toggle */}
          <button
            type="button"
            onClick={onToggleLabels}
            title={showAllLabels ? "Hide non-essential labels" : "Show all node labels"}
            className={`px-2 py-1 text-xs font-medium rounded-md border transition-colors flex items-center gap-1 ${
              showAllLabels
                ? "bg-[var(--accent-dim)] border-[var(--accent)] text-[var(--accent)]"
                : "border-[var(--border)] text-[var(--text-secondary)] hover:bg-[var(--surface-hover)]"
            }`}
          >
            <Tag className="size-3" />
            <span className="hidden md:inline">Labels</span>
          </button>

          {/* Rearrange Mode Toggle */}
          <button
            type="button"
            onClick={onToggleRearrange}
            title={rearrangeEnabled ? "Lock graph layout" : "Enable manual node dragging"}
            className={`px-2 py-1 text-xs font-medium rounded-md border transition-colors flex items-center gap-1 ${
              rearrangeEnabled
                ? "bg-amber-50 border-amber-300 text-amber-800"
                : "border-[var(--border)] text-[var(--text-secondary)] hover:bg-[var(--surface-hover)]"
            }`}
          >
            <Move className="size-3" />
            <span className="hidden md:inline">{rearrangeEnabled ? "Draggable" : "Rearrange"}</span>
          </button>

          {/* Fit to View */}
          <button
            type="button"
            onClick={onFitView}
            title="Fit graph to view"
            className="p-1.5 text-xs text-[var(--text-secondary)] border border-[var(--border)] rounded-md hover:bg-[var(--surface-hover)] transition-colors"
          >
            <Maximize2 className="size-3.5" />
          </button>

          {/* Reset Zoom/Pan */}
          <button
            type="button"
            onClick={onResetView}
            title="Reset zoom and center"
            className="p-1.5 text-xs text-[var(--text-secondary)] border border-[var(--border)] rounded-md hover:bg-[var(--surface-hover)] transition-colors"
          >
            <RotateCcw className="size-3.5" />
          </button>
        </div>
      </div>

      {/* Filter status bar */}
      <div className="flex items-center justify-between text-[11px] text-[var(--text-muted)] border-t border-[var(--border)] pt-2">
        <div className="flex items-center gap-1.5">
          <Filter className="size-3" />
          <span>
            Displaying <strong className="text-[var(--foreground)]">{totalFilteredNodes}</strong> of{" "}
            <strong>{totalNodes}</strong> entities in active viewport
          </span>
        </div>
        {rearrangeEnabled && (
          <span className="text-amber-700 bg-amber-50 px-1.5 py-0.5 rounded font-medium text-[10px]">
            Drag mode active: Click & drag nodes to customize view
          </span>
        )}
      </div>
    </div>
  );
}
