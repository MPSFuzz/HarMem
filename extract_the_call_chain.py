import networkx as nx
import matplotlib.pyplot as plt
from itertools import product

def load_call_graph(dot_file):
    try:
        G = nx.drawing.nx_pydot.read_dot(dot_file)
        return nx.DiGraph(G)
    except Exception as e:
        raise SystemExit(f"dot file load fail: {str(e)}")

def find_call_chain(graph:nx.DiGraph, target_func) -> list:
    target_node = None
    for node, data in graph.nodes(data=True):
        print(f"Node: {node}, Data: {data}")
        if 'label' in data and data['label'].strip('""').strip('{}') == target_func:
            target_node = node
            break  # 假设只有一个节点的标签是 "inverted_tree"

    if target_node is None:
        raise ValueError(f"Function with label '{target_func}' does not exist in the graph")
    
    print(target_node)
    
    roots = [n for n in graph.nodes if graph.in_degree(n) == 0] #获取所有根节点

    print(f"Roots: {roots}") # 添加这行
    
    valid_paths = set()
    found_count = 0 # 计数器，用于限制找到的路径数量

    reachable_roots = set() #存储从目标节点可以回溯到的根节点
    stack = [target_node] #用于深度优先搜索的栈
    visited = {target_node} #存储已访问的节点，防止循环
    predecessors = {node: [] for node in graph.nodes} #存储每个节点的前驱节点

    while stack: #实现深搜
        if len(reachable_roots) >= 10:
            break
        current_node = stack.pop()
        for predecessor in graph.predecessors(current_node):
            # 如果前驱节点尚未被访问
            if predecessor not in visited:
                visited.add(predecessor) # 标记为已访问
                predecessors[predecessor].append(current_node) # 记录前驱节点到当前节点的连接
                stack.append(predecessor) # 将前驱节点加入栈，继续向上游搜索
                if predecessor in roots:
                    reachable_roots.add(predecessor) # 将其添加到可到达的根节点集合中
    
    for root in reachable_roots:
        for path in nx.all_simple_paths(graph, source=root, target=target_node): # 使用NetworkX的all_simple_paths函数查找从当前根节点到目标节点的简单路径
            valid_paths.add(tuple(path))
            found_count += 1
            if found_count >= 10:
                return valid_paths  # 找到足够数量的路径后立即返回
    
    return [list(p) for p in valid_paths] # 返回所有有效路径的列表
def convert_to_call_chains(graph:nx.DiGraph, node_chains):
    call_chains = []
    for chain_node_ids in node_chains:
        function_names = []
        for node_id in chain_node_ids:
            if node_id in graph.nodes and 'label' in graph.nodes[node_id]:
                function_name = graph.nodes[node_id]['label'].strip('""').strip('{}')
                function_names.append(function_name)
            else:
                function_names.append(node_id) # 如果找不到标签，则使用原始节点 ID
        call_chains.append(function_names)
    return call_chains

def visualize_call_chain(original_graph:nx.DiGraph, node_chain,call_chain):
    plt.figure(figsize=(10, 6))
    subgraph = original_graph.subgraph(node_chain)
    pos = nx.spring_layout(subgraph, k=0.3)

    labels = {}
    for node in subgraph.nodes():
        if node in original_graph.nodes and 'label' in original_graph.nodes[node]:
            labels[node] = original_graph.nodes[node]['label'].strip('""').strip('{}')
        else:
            labels[node] = node

    nx.draw_networkx_nodes(subgraph, pos, node_size=500, node_color='skyblue')
    nx.draw_networkx_edges(subgraph, pos, edge_color='blue', arrowsize=20)
    nx.draw_networkx_labels(subgraph, pos, labels, font_size=10)

    plt.title("Call Chain")
    plt.axis('off')
    plt.show()

def extract_target_call_chain(dot_file: str, target_func: str) -> list:
    dot_file = dot_file
    target_func = target_func
    #target_func = "Node0x55fb1aff0d10"

    graph = load_call_graph(dot_file)
    print("load call graph success\n")

    try:
        node_chains = find_call_chain(graph, target_func)
    except ValueError as e:
        raise SystemExit(f"find call chain fail: {str(e)}")
    
    call_chains = convert_to_call_chains(graph, node_chains)
    print(f"\nCall chains (function names): {call_chains}")

    for i, (call_chain, node_chian) in enumerate(zip(call_chains, node_chains)):
        print(f"\nCall chain {i+1}: {call_chain}")
        #visualize_call_chain(graph, node_chian,call_chain)
        print("\n")
    
    return call_chains

if __name__ == "__main__":
    extract_target_call_chain()