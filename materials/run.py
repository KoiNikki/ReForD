import os
import glob
import time
import argparse
from collector import SysdigLogProcessor
from reford import ProvenanceReforder
from utils import GraphUtils

parser = argparse.ArgumentParser(description='Process log files and generate graphs.')
parser.add_argument('--log', type=str, required=True, help='Directory containing .log files')
parser.add_argument('--output', type=str, required=True, help='Output directory for graphs')
args = parser.parse_args()

# 获取当前时间戳
timestamp = time.strftime("%Y%m%d_%H%M%S")
raw_graph_dir = os.path.join(args.output, timestamp, 'raw_graph')
reduced_graph_dir = os.path.join(args.output, timestamp, 'reduced_graph')
info_file_path = os.path.join(args.output, timestamp, 'info.txt')
os.makedirs(raw_graph_dir, exist_ok=True)
os.makedirs(reduced_graph_dir, exist_ok=True)

# 获取--log指定文件夹中所有.log文件
log_files = glob.glob(os.path.join(args.log, '*.log'))

for log_path in log_files:
    log_basename = os.path.basename(log_path)
    
    # log -> graph
    processor = SysdigLogProcessor(log_path)
    digraph = processor.process_log_file()
    graph = GraphUtils.from_digraph(digraph)
    # size
    GraphUtils.save_graph_size(f"{log_basename.replace('.log', '')}-raw", graph, info_file_path)
    # save
    raw_graph_filename = log_basename.replace('.log', '.json')
    GraphUtils.save_graph(os.path.join(raw_graph_dir, raw_graph_filename), graph)

    # graph -> reforded graph
    reducer = ProvenanceReforder()
    reduced_graph = reducer.reduce_with_graph(graph)
    # size
    GraphUtils.save_graph_size(f"{log_basename.replace('.log', '')}-reduced", reduced_graph, info_file_path)
    # save
    reduced_graph_filename = log_basename.replace('.log', '_reduced.json')
    GraphUtils.save_graph(os.path.join(reduced_graph_dir, reduced_graph_filename), reduced_graph)

print(f"Processed {len(log_files)} log files. Graphs saved in {args.output}/{timestamp}/")
