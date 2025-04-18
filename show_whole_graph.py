import networkx as nx
import matplotlib.pyplot as plt
import argparse
import sys

def load_call_graph(dot_file: str) -> nx.DiGraph:
    """
    从 .dot 文件加载图形。
    如果失败，则打印错误信息并退出程序。
    """
    try:
        # 使用 nx_pydot，它需要 pydot 库 (graphviz的Python接口)
        G = nx.drawing.nx_pydot.read_dot(dot_file)
        return nx.DiGraph(G)
    except FileNotFoundError:
        sys.exit(f"错误: 文件未找到 '{dot_file}'")
    except Exception as e:
        sys.exit(f"错误: 加载 .dot 文件失败。请确保安装了 'pydot' 和 Graphviz。\n原因: {e}")

def visualize_full_graph(graph: nx.DiGraph):
    """
    可视化完整的调用图。
    """
    print(f"正在可视化图形... (包含 {len(graph.nodes())} 个节点和 {len(graph.edges())} 条边)")
    print("对于大图，这可能需要一些时间，请稍候...")
    
    plt.figure(figsize=(25, 20))

    # 对于大图，kamada_kawai_layout 通常比 spring_layout 更快且布局更清晰
    # 如果图不是连通的，它会报错，所以我们添加一个try-except来处理
    try:
        pos = nx.kamada_kawai_layout(graph)
    except nx.NetworkXError:
        print("警告: 图不是连通的，回退到 spring_layout。布局可能需要更长时间。")
        pos = nx.spring_layout(graph, k=0.5, iterations=50)

    # 提取所有节点的标签用于显示，如果不存在则使用节点ID
    labels = {node: data.get('label', node).strip('""').strip('{}') for node, data in graph.nodes(data=True)}

    nx.draw_networkx_nodes(graph, pos, node_size=250, node_color='skyblue', alpha=0.9)
    nx.draw_networkx_edges(graph, pos, edge_color='gray', arrowsize=12, alpha=0.7)

    # 为了避免标签重叠，只在节点数较少时显示标签
    if len(graph) < 200:
        nx.draw_networkx_labels(graph, pos, labels, font_size=7, verticalalignment='center')
    else:
        print("节点过多，为保持清晰，已跳过绘制函数名标签。")
        
    plt.title("Call Graph Visualization", size=20)
    plt.axis('off')
    plt.tight_layout()
    plt.show()

def main():
    """
    主函数，用于解析命令行参数并启动可视化。
    """
    # 创建一个参数解析器
    parser = argparse.ArgumentParser(description="从 .dot 文件中加载并可视化一个调用图。")
    
    # 添加一个必须的位置参数 'dot_file'
    parser.add_argument("dot_file", help="需要可视化的 .dot 文件的路径。")
    
    # 解析命令行传入的参数
    args = parser.parse_args()
    
    # 执行主逻辑
    graph = load_call_graph(args.dot_file)
    visualize_full_graph(graph)

if __name__ == "__main__":
    main()