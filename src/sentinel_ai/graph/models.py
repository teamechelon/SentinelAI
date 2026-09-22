from dataclasses import dataclass, field
from typing import Any

@dataclass(frozen=True)
class GraphNode:
    node_id: str
    node_type: str
    label: str
    metadata: dict[str, Any]

@dataclass(frozen=True)
class GraphEdge:
    source_id: str
    target_id: str
    edge_type: str
    metadata: dict[str, Any]

@dataclass(frozen=True)
class GraphFinding:
    finding_type: str
    severity: str
    entities: tuple[str, ...]
    supporting_events: tuple[str, ...]
    supporting_attack_runs: tuple[str, ...]
    observed_relationship: str
    explanation: str

class SecurityGraph:
    def __init__(self):
        self.nodes: dict[str, GraphNode] = {}
        self.edges: list[GraphEdge] = []
        self.findings: list[GraphFinding] = []
        
    def add_node(self, node: GraphNode) -> None:
        self.nodes[node.node_id] = node
        
    def add_edge(self, edge: GraphEdge) -> None:
        # Avoid exact duplicates
        for existing in self.edges:
            if (existing.source_id == edge.source_id and 
                existing.target_id == edge.target_id and 
                existing.edge_type == edge.edge_type):
                return
        self.edges.append(edge)
        
    def neighbors(self, node_id: str) -> list[GraphNode]:
        neighbor_ids = set()
        for edge in self.edges:
            if edge.source_id == node_id:
                neighbor_ids.add(edge.target_id)
            elif edge.target_id == node_id:
                neighbor_ids.add(edge.source_id)
        return [self.nodes[nid] for nid in neighbor_ids if nid in self.nodes]
        
    def nodes_by_type(self, node_type: str) -> list[GraphNode]:
        return [node for node in self.nodes.values() if node.node_type == node_type]
        
    def edges_for(self, node_id: str) -> list[GraphEdge]:
        return [edge for edge in self.edges if edge.source_id == node_id or edge.target_id == node_id]
        
    def findings_for(self, entity_id: str) -> list[GraphFinding]:
        return [finding for finding in self.findings if entity_id in finding.entities]
