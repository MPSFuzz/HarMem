import networkx as nx
import matplotlib.pyplot as plt
import random
from typing import Any


def load_call_graph(dot_file):
    try:
        G = nx.drawing.nx_pydot.read_dot(dot_file)
        return nx.DiGraph(G)
    except Exception as e:
        raise SystemExit(f"dot file load fail: {str(e)}")
    
def get_label_by_Node(graph:nx.DiGraph ,node) -> Any:
    labels = []

    for n in node:
        label = graph.nodes[n].get('label', '')
        if label:
            labels.append(label.strip('""').strip('{}'))
    
    return labels

def get_Node_by_label(graph:nx.DiGraph, labels) -> Any:
    nodes = []

    for node, data in graph.nodes(data=True):
        if 'label' in data and data['label'].strip('""').strip('{}') in labels:
            nodes.append(node)

    return nodes

def convert_to_call_chain(graph:nx.DiGraph, node_chain):
    lable_chain = []

    for node_id in node_chain:
        if node_id in graph.nodes and 'label' in graph.nodes[node_id]:
            function_name = graph.nodes[node_id]['label'].strip('""').strip('{}')
            lable_chain.append(function_name)
        else:   
            lable_chain.append(node_id) # 如果找不到标签，则使用原始节点 ID
    return lable_chain

def get_root_apis(graph:nx.DiGraph, target_func) ->list : 
    target_node = None
    for node, data in graph.nodes(data=True):
        print(f"Node: {node}, Data: {data}")
        if 'label' in data and data['label'].strip('""').strip('{}') == target_func:
            target_node = node
            break  # 假设只有一个节点的标签是 "inverted_tree"

    if target_node is None:
        raise ValueError(f"Function with label '{target_func}' does not exist in the graph")
    
    print(target_node)

    reachable_root_nodes = set()
    stack =  [target_node]
    visited = {target_node}

    # reverse DFS to find all reachable roots from the target node
    while stack:
        current_node = stack.pop()
        for predecessor in graph.predecessors(current_node):
            if predecessor not in visited:
                visited.add(predecessor)
                if graph.in_degree(predecessor) == 0:
                    reachable_root_nodes.add(predecessor)
                else:
                    stack.append(predecessor)
    
    reachable_roots = get_label_by_Node(graph, reachable_root_nodes)

    print(f"Roots after reverse DFS: {reachable_roots}")

    return reachable_roots


def extract_target_call_chain(graph:nx.DiGraph, target_func, root_apis: list) -> dict:
    target_node = get_Node_by_label(graph=graph, labels=target_func)
    root_nodes = get_Node_by_label(graph=graph, labels=root_apis)

    result = {}
    for root_api in root_nodes:
        all_paths = nx.all_simple_paths(graph, source=root_api, target=target_node, cutoff=7)

        candidate_paths = [path for path in all_paths if 5 <= len(path) <= 7]

        if candidate_paths:
            chosen_path = random.choice(candidate_paths)
            chosen_path = get_label_by_Node(graph=graph, node=chosen_path)
            result[root_api] = chosen_path

    return result


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


if __name__ == "__main__":
    extract_target_call_chain()