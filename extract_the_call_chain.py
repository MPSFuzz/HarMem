import networkx as nx
import matplotlib.pyplot as plt
from itertools import product
from itertools import islice

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

    print(f"Roots: {roots}")
    
    valid_paths = set()

    for root in roots:
        if not nx.has_path(graph, root, target_node):
            continue

        candiate_paths = nx.algorithms.simple_paths.shortest_path(graph, source=root, target=target_node)

        for path in candiate_paths:
            valid_paths.add(tuple(path))
            if len(valid_paths) >= 5:
                break

    return list(valid_paths)

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