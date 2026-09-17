import networkx as nx
import matplotlib.pyplot as plt
import argparse
import sys

def load_call_graph(dot_file: str) -> nx.DiGraph:
    """
    Load a graph from a .dot file.
    If it fails, print an error message and exit the program.
    """
    try:
        # Use nx_pydot, which requires the pydot library (Python interface to Graphviz)
        G = nx.drawing.nx_pydot.read_dot(dot_file)
        return nx.DiGraph(G)
    except FileNotFoundError:
        sys.exit(f"Error: file not found '{dot_file}'")
    except Exception as e:
        sys.exit(f"Error: failed to load .dot file. Please make sure 'pydot' and Graphviz are installed.\nReason: {e}")

def visualize_full_graph(graph: nx.DiGraph):
    """
    Visualize the complete call graph.
    """
    print(f"Visualizing graph... ({len(graph.nodes())} nodes and {len(graph.edges())} edges)")
    print("For large graphs, this may take some time, please wait...")
    
    plt.figure(figsize=(25, 20))

    # For large graphs, kamada_kawai_layout is usually faster and produces a cleaner layout than spring_layout
    # It raises an error if the graph is not connected, so we add a try-except to handle it
    try:
        pos = nx.kamada_kawai_layout(graph)
    except nx.NetworkXError:
        print("Warning: graph is not connected, falling back to spring_layout. The layout may take longer.")
        pos = nx.spring_layout(graph, k=0.5, iterations=50)

    # Extract labels for all nodes for display, falling back to the node ID if absent
    labels = {node: data.get('label', node).strip('""').strip('{}') for node, data in graph.nodes(data=True)}

    nx.draw_networkx_nodes(graph, pos, node_size=250, node_color='skyblue', alpha=0.9)
    nx.draw_networkx_edges(graph, pos, edge_color='gray', arrowsize=12, alpha=0.7)

    # To avoid overlapping labels, only draw labels when the number of nodes is small
    if len(graph) < 200:
        nx.draw_networkx_labels(graph, pos, labels, font_size=7, verticalalignment='center')
    else:
        print("Too many nodes; skipping function name labels to keep the plot clear.")
        
    plt.title("Call Graph Visualization", size=20)
    plt.axis('off')
    plt.tight_layout()
    plt.show()

def main():
    parser = argparse.ArgumentParser(description="Load and visualize a call graph from a .dot file.")
    
    parser.add_argument("dot_file", help="Path to the .dot file to visualize.")
    
    args = parser.parse_args()
    
    graph = load_call_graph(args.dot_file)
    visualize_full_graph(graph)

if __name__ == "__main__":
    main()