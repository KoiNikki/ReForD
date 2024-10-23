import json
import math
import os
import random
from loguru import logger
import config
from utils import GraphUtils


class ProvenanceReforder:
    def __init__(self):
        random.seed(42)
        self.LAMBDA = 0.05
        self.WRITE_THRESHOLD = 3
        self.OPEN_THRESHOLD = 10

    def _get_prov_action(self, syscall):
        if syscall in config.SYSCALL_PROC_START:
            return "proc_start"
        elif syscall in config.SYSCALL_PROC_END_ACTIVE:
            return "proc_end_active"
        elif syscall in config.SYSCALL_FILE_EXEC:
            return "file_exec"
        elif syscall in config.SYSCALL_FILE_OPEN:
            return "file_open"
        elif syscall in config.SYSCALL_FILE_CREAT:
            return "file_creat"
        elif syscall in config.SYSCALL_FILE_WRITE:
            return "file_write"
        elif syscall in config.SYSCALL_FILE_READ:
            return "file_read"
        elif syscall in config.SYSCALL_FILE_DEL:
            return "file_del"
        else:
            return "unknown"

    def _calculate_file_attributes(self, graph):
        files_attrs = {}
        for edge in graph["links"]:
            action = self._get_prov_action(edge["syscall"])
            target_node_id = edge["target"]
            files_attrs.setdefault(target_node_id, [0, 0, 0, 0])

            if action == "file_read":
                files_attrs[target_node_id][0] += 1
            elif action in ["file_creat", "file_write", "file_del"]:
                files_attrs[target_node_id][1] += 1
            elif action == "file_exec":
                files_attrs[target_node_id][2] += 1
            elif action == "file_open":
                files_attrs[target_node_id][1] *= math.exp(-self.LAMBDA)
                files_attrs[target_node_id][3] += 1

        return files_attrs

    def _reduce_graph_edges(self, graph, files_attrs):
        reduced_edges = []
        maybe_attack_edges = []

        for edge in graph["links"]:
            action = self._get_prov_action(edge["syscall"])

            if self._is_process_event(edge):
                reduced_edges.append(edge)
            elif self._is_socket_write_event(edge, action):
                reduced_edges.append(edge)
            elif self._is_file_event(edge, files_attrs):
                reduced_edges.append(edge)
            elif action == "unknown":
                reduced_edges.append(edge)
            else:
                maybe_attack_edges.append(edge)

        self._log_maybe_attack_edges(maybe_attack_edges)
        self._fix_random_partial_edges(graph, reduced_edges)
        graph["links"] = reduced_edges

        return graph

    def _is_process_event(self, edge):
        return edge["source_type"] == "process" and edge["target_type"] == "process"

    def _is_socket_write_event(self, edge, action):
        return (
            edge["source_type"] == "process"
            and edge["target_type"]
            in ["pipe", "ipv4_socket", "ipv6_socket", "unix_socket"]
            and action == "file_write"
        )

    def _is_file_event(self, edge, files_attrs):
        if edge["source_type"] == "process" and edge["target_type"] in ["file", "dir"]:
            target_node_id = edge["target"]
            read_cnt, write_cnt, exec_cnt, open_cnt = files_attrs[target_node_id]
            if (read_cnt > 0 and write_cnt > 0) or exec_cnt > 0:
                return True
            elif write_cnt > 0 and open_cnt > 0:
                return (
                    write_cnt <= self.WRITE_THRESHOLD or open_cnt >= self.OPEN_THRESHOLD
                )
        return False

    def _log_maybe_attack_edges(self, maybe_attack_edges):
        logger.debug(f"maybe_attack_edges: {len(maybe_attack_edges)}")

    def _fix_random_partial_edges(self, graph, reduced_edges):
        if os.getenv("FIX", 0):
            reduced_edges += random.choices(
                graph["links"], k=int(0.2 * len(graph["links"]))
            )

    def reduce_with_file(self, file_path: str):
        graph = GraphUtils.load_graph(file_path)
        files_attrs = self._calculate_file_attributes(graph)
        reduced_graph = self._reduce_graph_edges(graph, files_attrs)
        GraphUtils.remove_isolated_nodes(reduced_graph)
        return reduced_graph

    def reduce_with_graph(self, graph: dict):
        files_attrs = self._calculate_file_attributes(graph)
        reduced_graph = self._reduce_graph_edges(graph, files_attrs)
        GraphUtils.remove_isolated_nodes(reduced_graph)
        return reduced_graph


def main():
    reducer = ProvenanceReforder()
    # reduced_graph = reducer.reduce_with_file("")
    # reduced_graph_dict = reducer.reduce_with_graph(graph)
