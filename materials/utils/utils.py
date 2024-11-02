import json
import os


class GraphUtils:
    @staticmethod
    def load_graph(path: str):
        if os.path.isfile(path):
            with open(path, "r") as f:
                return json.load(f)

    @staticmethod
    def save_graph(path: str, data: dict):
        with open(path, "w") as f:
            json.dump(data, f)

    @staticmethod
    def remove_isolated_nodes(graph: dict):
        valid_node_ids = set()
        for link in graph["links"]:
            valid_node_ids.add(link["source"])
            valid_node_ids.add(link["target"])

        new_nodes = list()
        for node in graph["nodes"]:
            if node["id"] in valid_node_ids:
                new_nodes.append(node)

        graph["nodes"] = new_nodes
        
    @staticmethod
    def from_digraph(digraph):
        graph = {"nodes": [], "links": []}
        for node in digraph.nodes():
            graph["nodes"].append({"id": node})
        for node, neighbors in digraph.adjacency():
            for neighbor in neighbors:
                event = {
                    "source": node,
                    "target": neighbor,
                    **digraph[node][neighbor],
                }
                graph["links"].append(event)
        return graph