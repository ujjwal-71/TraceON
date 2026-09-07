import networkx as nx
from typing import Dict, Any, List


class ThreatGraphCorrelator:
    """Builds cross-case campaign correlation graphs for Cytoscape.js."""

    def __init__(self):
        self.graph = nx.Graph()
        self.ingested_cases = set()

    def ingest_case(self, case_id: str, case_data: Dict[str, Any]):
        if case_id in self.ingested_cases:
            return

        headers = case_data.get("headers", {})
        origin_geo = case_data.get("origin_geo", {})
        threat = case_data.get("threat_summary", {})
        flagged = threat.get("flagged_engines_count", 0)

        case_node = f"CASE_{case_id[:8]}"
        color = "#EF4444" if flagged >= 3 else ("#F59E0B" if flagged >= 1 else "#10B981")
        self.graph.add_node(case_node, type="CASE", label=f"Case {case_id[:8]}", color=color)

        # 1. Sender Node
        sender = headers.get("from_address")
        if sender:
            s_node = f"SENDER_{sender}"
            self.graph.add_node(s_node, type="SENDER", label=sender, color="#3B82F6")
            self.graph.add_edge(case_node, s_node, label="SENT_BY")

        # 2. IP Node
        ip = origin_geo.get("origin_ip") or case_data.get("hop_trace", {}).get("origin_ip")
        if ip:
            ip_node = f"IP_{ip}"
            self.graph.add_node(ip_node, type="IP", label=f"{ip} ({origin_geo.get('country_code', 'XX')})", color="#8B5CF6")
            self.graph.add_edge(case_node, ip_node, label="ORIGIN_IP")

        self.ingested_cases.add(case_id)

    def export_cytoscape_elements(self) -> Dict[str, List[Dict[str, Any]]]:
        nodes = []
        edges = []

        for node_id, attrs in self.graph.nodes(data=True):
            nodes.append({
                "data": {
                    "id": node_id,
                    "label": attrs.get("label", node_id),
                    "type": attrs.get("type", "NODE"),
                    "color": attrs.get("color", "#64748B")
                }
            })

        for u, v, attrs in self.graph.edges(data=True):
            edges.append({
                "data": {
                    "id": f"{u}_{v}",
                    "source": u,
                    "target": v,
                    "label": attrs.get("label", "RELATED")
                }
            })

        return {"nodes": nodes, "edges": edges}
