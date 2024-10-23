#!/usr/bin/python
# -*- coding:utf-8 -*-
# @function: process sysdig log files and generate graph data.

import argparse
import networkx as nx
from loguru import logger
import config

class LogParser:
    @staticmethod
    def get_fd_type(fd_type_str):
        fd_mapping = {"f": "file", "d": "dir", "p": "pipe", "u": "unix_socket"}
        for prefix in ("4", "6"):
            if fd_type_str.startswith(prefix):
                return f"ipv{prefix}_socket"
        return fd_mapping.get(fd_type_str, "unknown")

    @staticmethod
    def get_f_path(f_path_from_regex):
        if f_path_from_regex is None:
            return None
        if "(/" in f_path_from_regex:
            f_path_from_regex = "/" + f_path_from_regex[:-1].split("(/")[1]
        return f_path_from_regex


class SysdigLogProcessor:
    def __init__(self, log_file, container_mode=True, ignore_no_return=False):
        self.log_file = log_file
        self.container_mode = container_mode
        self.ignore_no_return = ignore_no_return
        self.entities = {}
        self.events = []
        self.write_stack = []
        self.read_stack = []

    # Use this method
    def process_log_file(self):
        with open(self.log_file) as fh:
            for line in fh:
                self._process_line(line.strip())
        return self.build_graph()

    def _process_line(self, line):
        if not line:
            return

        parsed_line = self._parse_line(line)
        if parsed_line is None:
            return

        ts, container_name, pname, pid, syscall_dir, syscall, syscall_args = parsed_line

        if syscall_dir == ">":
            if syscall in config.SYSCALL_PROC_END_ACTIVE:
                self._handle_proc_end_out(
                    ts, pname, pid, syscall, syscall_args, container_name
                )
            elif syscall in config.SYSCALL_FILE_WRITE:
                self._handle_file_write_out(
                    ts, pname, pid, syscall, syscall_args, container_name
                )
            elif syscall in config.SYSCALL_FILE_READ:
                self._handle_file_read_out(
                    ts, pname, pid, syscall, syscall_args, container_name
                )
            elif syscall in config.SYSCALL_FILE_OPEN:
                self._handle_file_open_out(
                    ts, pname, pid, syscall, syscall_args, container_name
                )
        elif syscall_dir == "<":
            if syscall in config.SYSCALL_PROC_START:
                self._handle_proc_start_in(
                    ts, pname, pid, syscall, syscall_args, container_name
                )
            elif syscall in config.SYSCALL_FILE_EXEC:
                self._handle_file_exec_in(
                    ts, pname, pid, syscall, syscall_args, container_name
                )
            elif syscall in config.SYSCALL_FILE_OPEN:
                self._handle_file_open_in(
                    ts, pname, pid, syscall, syscall_args, container_name
                )
            elif syscall in config.SYSCALL_FILE_CREAT:
                self._handle_file_creat_in(
                    ts, pname, pid, syscall, syscall_args, container_name
                )
            elif syscall in config.SYSCALL_FILE_DEL:
                self._handle_file_del_in(
                    ts, pname, pid, syscall, syscall_args, container_name
                )
            elif syscall in config.SYSCALL_FILE_WRITE:
                self._handle_file_write_in(
                    ts, pname, pid, syscall, syscall_args, container_name
                )
            elif syscall in config.SYSCALL_FILE_READ:
                self._handle_file_read_in(
                    ts, pname, pid, syscall, syscall_args, container_name
                )

    def _parse_line(self, line):
        tokens = line.split(" ")
        if self.container_mode:
            if len(tokens) < 9:
                return None
            (
                _,
                ts,
                _,
                container_name,
                _,
                pname,
                pid_str,
                syscall_dir,
                syscall,
                *syscall_args,
            ) = tokens
            pid, _ = self._extract_pid(pid_str)
        else:
            if len(tokens) < 7:
                return None
            (_, ts, _, pname, pid_str, syscall_dir, syscall, *syscall_args) = tokens
            container_name = "localhost"
            pid = self._extract_pid(pid_str, include_container=False)
        syscall_args = " ".join(syscall_args)

        return ts, container_name, pname, pid, syscall_dir, syscall, syscall_args

    @staticmethod
    def _extract_pid(pid_str, include_container=True):
        if include_container:
            return pid_str[1:-1].split(":")
        else:
            return pid_str[1:-1]

    def _handle_proc_end_out(
        self, ts, pname, pid, syscall, syscall_args, container_name
    ):
        match = config.REGEX_PROC_END_ACTIVE.match(syscall_args)
        if match:
            success = match.group("ret") == "0"
            uni_pid = f"{pname}__{pid}"
            self._add_entity(uni_pid, pid, pname, "process", container_name)
            self._add_event(uni_pid, "", ts, syscall, success, "process", "")

    def _handle_file_write_out(
        self, ts, pname, pid, syscall, syscall_args, container_name
    ):
        match = config.REGEX_FILE_WRITE_ARGS.match(syscall_args)
        if match:
            self._add_to_write_read_stack(
                ts, pname, pid, syscall, match, container_name
            )

    def _handle_file_read_out(
        self, ts, pname, pid, syscall, syscall_args, container_name
    ):
        match = config.REGEX_FILE_READ_ARGS.match(syscall_args)
        if match:
            self._add_to_write_read_stack(
                ts, pname, pid, syscall, match, container_name, read=True
            )

    def _add_to_write_read_stack(
        self, ts, pname, pid, syscall, match, container_name, read=False
    ):
        f_type = match.group("fd_type")
        f_path = LogParser.get_f_path(match.group("fd_content"))
        uni_pid = f"{pname}__{pid}"
        stack = self.read_stack if read else self.write_stack
        stack.append((ts, container_name, uni_pid, pid, syscall, f_type, f_path))

    def _handle_file_open_out(
        self, ts, pname, pid, syscall, syscall_args, container_name
    ):
        if self.ignore_no_return:
            return
        match = config.REGEX_DIR_OPEN.match(syscall_args)
        if match:
            fd_num = match.group("fd_num")
            success = "AT_FDCWD" in fd_num or "-" not in fd_num
            if success:
                f_path = LogParser.get_f_path(match.group("fd_content")).split("(")[-1]
                uni_pid = f"{pname}__{pid}"
                uni_f_path = f"{container_name}__{f_path}"
                self._add_entity(uni_pid, pid, pname, "process", container_name)
                self._add_f_entity(uni_f_path, f_path, "dir", container_name)
                self._add_event(
                    uni_pid, uni_f_path, ts, syscall, True, "process", "dir"
                )

    def _handle_proc_start_in(
        self, ts, pname, pid, syscall, syscall_args, container_name
    ):
        res = config.REGEX_PROC_START.match(syscall_args)
        if res:
            ppid, ppname = res.group("ppid"), res.group("ppname")
            uni_pid = f"{pname}__{pid}"
            uni_ppid = f"{ppname}__{ppid}"
            self._add_entity(uni_ppid, ppid, ppname, "process", container_name)
            self._add_entity(uni_pid, pid, pname, "process", container_name)
            self._add_event(uni_ppid, uni_pid, ts, syscall, True, "process", "process")
        else:
            logger.debug(f"syscall: `{syscall}`, args: `{syscall_args}`\n")

    def _handle_file_exec_in(
        self, ts, pname, pid, syscall, syscall_args, container_name
    ):
        res = config.REGEX_FILE_EXEC.match(syscall_args)
        if res:
            success = "-" not in res.group("res")
            ppid, ppname = res.group("ppid"), res.group("ppname")
            uni_pid = f"{pname}__{pid}"
            uni_ppid = f"{ppname}__{ppid}"
            self._add_entity(uni_ppid, ppid, ppname, "process", container_name)
            self._add_entity(uni_pid, pid, pname, "process", container_name)
            self._add_event(
                uni_ppid, uni_pid, ts, syscall, success, "process", "process"
            )
        else:
            logger.debug(f"syscall: `{syscall}`, args: `{syscall_args}`\n")

    def _handle_file_open_in(
        self, ts, pname, pid, syscall, syscall_args, container_name
    ):
        res = config.REGEX_FILE_OPEN.match(syscall_args)
        if res:
            success = "-" not in res.group("fd_num")
            if success:
                f_type, f_path = res.group("fd_type"), LogParser.get_f_path(
                    res.group("fd_content")
                )
                if f_path:
                    uni_pid = f"{pname}__{pid}"
                    uni_f_path = f"{container_name}__{f_path}"
                    self._add_entity(uni_pid, pid, pname, "process", container_name)
                    self._add_f_entity(
                        uni_f_path,
                        f_path,
                        LogParser.get_fd_type(f_type),
                        container_name,
                    )
                    self._add_event(
                        uni_pid,
                        uni_f_path,
                        ts,
                        syscall,
                        True,
                        "process",
                        LogParser.get_fd_type(f_type),
                    )
        else:
            logger.debug(f"syscall: `{syscall}`, args: `{syscall_args}`\n")

    def _handle_file_creat_in(
        self, ts, pname, pid, syscall, syscall_args, container_name
    ):
        res = config.REGEX_FILE_CREAT.match(syscall_args)
        if res:
            success = "-" not in res.group("fd_num")
            f_type, f_path = res.group("fd_type"), LogParser.get_f_path(
                res.group("fd_content")
            )
            uni_pid = f"{pname}__{pid}"
            uni_f_path = f"{container_name}__{f_path}"
            self._add_entity(uni_pid, pid, pname, "process", container_name)
            self._add_f_entity(
                uni_f_path, f_path, LogParser.get_fd_type(f_type), container_name
            )
            self._add_event(
                uni_pid,
                uni_f_path,
                ts,
                syscall,
                success,
                "process",
                LogParser.get_fd_type(f_type),
            )
        else:
            logger.debug(f"syscall: `{syscall}`, args: `{syscall_args}`\n")

    def _handle_file_del_in(
        self, ts, pname, pid, syscall, syscall_args, container_name
    ):
        res = config.REGEX_FILE_DEL_UNLINK.match(syscall_args)
        if res:
            self._process_file_del(ts, pname, pid, syscall, res, container_name)
        else:
            res = config.REGEX_FILE_DEL_UNLINKAT.match(syscall_args)
            if res:
                self._process_file_del(ts, pname, pid, syscall, res, container_name)
            else:
                logger.debug(f"syscall: `{syscall}`, args: `{syscall_args}`\n")

    def _process_file_del(self, ts, pname, pid, syscall, res, container_name):
        success = "-" not in res.group("res")
        uni_pid = f"{pname}__{pid}"
        f_path = LogParser.get_f_path(res.group("path") or res.group("name"))
        uni_f_path = f"{container_name}__{f_path}"
        self._add_entity(uni_pid, pid, pname, "process", container_name)
        self._add_event(uni_pid, uni_f_path, ts, syscall, success, "process", "file")

    def _handle_file_write_in(
        self, ts, pname, pid, syscall, syscall_args, container_name
    ):
        res = config.REGEX_FILE_WRITE_RES.match(syscall_args)
        if res and self.write_stack:
            self._process_file_io(
                ts, pname, pid, syscall, res, container_name, self.write_stack
            )
        else:
            logger.debug(f"syscall: `{syscall}`, args: `{syscall_args}`\n")

    def _handle_file_read_in(
        self, ts, pname, pid, syscall, syscall_args, container_name
    ):
        res = config.REGEX_FILE_READ_RES.match(syscall_args)
        if res and self.read_stack:
            self._process_file_io(
                ts, pname, pid, syscall, res, container_name, self.read_stack
            )
        else:
            logger.debug(f"syscall: `{syscall}`, args: `{syscall_args}`\n")

    def _process_file_io(self, ts, pname, pid, syscall, res, container_name, stack):
        ts, container_name, uni_pid, pid, syscall, f_type, f_path = stack.pop()
        success = "-" not in res.group("res")
        if f_path:
            if LogParser.get_fd_type(f_type) in ["ipv4 socket", "ipv6 socket"]:
                sock_pair = f_path.split("->")
                if len(sock_pair) == 2:
                    f_path = sock_pair[1]
            uni_f_path = f"{container_name}__{f_path}"
            self._add_entity(uni_pid, pid, pname, "process", container_name)
            self._add_f_entity(
                uni_f_path, f_path, LogParser.get_fd_type(f_type), container_name
            )
            self._add_event(
                uni_pid,
                uni_f_path,
                ts,
                syscall,
                success,
                "process",
                LogParser.get_fd_type(f_type),
            )

    def _add_entity(self, uni_id, id, name, entity_type, host):
        if uni_id not in self.entities:
            self.entities[uni_id] = {
                "pid": id,
                "pname": name,
                "type": entity_type,
                "host": host,
            }

    def _add_f_entity(self, uni_path, path, entity_type, host):
        if uni_path not in self.entities:
            self.entities[uni_path] = {"path": path, "type": entity_type, "host": host}

    def _add_event(
        self, source, target, ts, syscall, success, source_type, target_type
    ):
        self.events.append(
            (
                source,
                target,
                {
                    "ts": ts,
                    "syscall": syscall,
                    "success": success,
                    "source_type": source_type,
                    "target_type": target_type,
                },
            )
        )

    def build_graph(self):
        logger.info(f"Write stack with no return: `{self.write_stack}`")
        logger.info(f"Read stack with no return: `{self.read_stack}`")
        logger.info(f"{len(self.entities)} entities and {len(self.events)} events")

        g = nx.DiGraph()
        g.add_nodes_from(self.entities.items())
        g.add_edges_from(filter(lambda e: e[2]["syscall"] != "procexit", self.events))
        logger.info(g)

        return g


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-L", "--log", required=True, help="Path to the sysdig log file"
    )
    args = parser.parse_args()

    processor = SysdigLogProcessor(args.log)
    prov_graph = processor.process_log_file()

    # Optional: Uncomment to visualize or save the graph
    # nx.write_gexf(prov_graph, "temp/temp1.gexf")

    # plt.figure(figsize=(12, 8))
    # pos = nx.spring_layout(prov_graph)
    # nx.draw(prov_graph, pos, with_labels=True, node_size=700, node_color='lightblue', font_size=10, font_weight='bold', edge_color='gray')
    # plt.title("Prov Graph Visualization")
    # plt.show()


if __name__ == "__main__":
    main()
