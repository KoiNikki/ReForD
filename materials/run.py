import os
import glob
import time
import argparse
from collector import SysdigLogProcessor
from reford import ProvenanceReforder
from utils import GraphUtils

# 命令行参数解析
parser = argparse.ArgumentParser(description='Process log files and generate graphs.')
parser.add_argument('--log', type=str, required=True, help='Directory containing .log files')
parser.add_argument('--output', type=str, required=True, help='Output directory for graphs')
args = parser.parse_args()

# 获取当前时间戳
timestamp = time.strftime("%Y%m%d_%H%M%S")
raw_graph_dir = os.path.join(args.output, timestamp, 'raw_graph')
reduced_graph_dir = os.path.join(args.output, timestamp, 'reduced_graph')

# 创建输出目录
os.makedirs(raw_graph_dir, exist_ok=True)
os.makedirs(reduced_graph_dir, exist_ok=True)

# 获取所有.log文件
log_files = glob.glob(os.path.join(args.log, '*.log'))

for log_path in log_files:
    # log -> graph
    processor = SysdigLogProcessor(log_path)
    digraph = processor.process_log_file()
    graph = GraphUtils.from_digraph(digraph)

    raw_graph_filename = os.path.basename(log_path).replace('.log', '.json')
    GraphUtils.save_graph(os.path.join(raw_graph_dir, raw_graph_filename), graph)

    # graph -> reforded graph
    reducer = ProvenanceReforder()
    reduced_graph = reducer.reduce_with_graph(graph)

    reduced_graph_filename = os.path.basename(log_path).replace('.log', '_reduced.json')
    GraphUtils.save_graph(os.path.join(reduced_graph_dir, reduced_graph_filename), reduced_graph)

print(f"Processed {len(log_files)} log files. Graphs saved in {args.output}/{timestamp}/")
