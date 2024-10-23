from collector import SysdigLogProcessor
from reford import ProvenanceReforder
from utils import GraphUtils
LOG_PATH = "data/cve-2019-9193/cve-2019-9193-attack-1.log"

processor = SysdigLogProcessor(LOG_PATH)
digraph =  processor.process_log_file()
graph = GraphUtils.digraph_to_json(digraph)

reducer = ProvenanceReforder()
graph = reducer.reduce_with_graph(GraphUtils.digraph_to_json(digraph))
