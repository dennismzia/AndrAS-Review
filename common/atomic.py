class DFDNode:
    def __init__(self, name : str, type: str, permission: list(), connected_nodes: list(), trust_boundary: str):
        self.name = name
        self.type = type
        self.permission = permission
        self.connected_nodes = connected_nodes
        self.trust_boundary = trust_boundary


class DFDGraph:
    def __init__(self, nodes: list()):
        self.nodes = nodes

    def add_node(self, node: DFDNode):
        if self.check_node_exist(self.nodes, node):
            self.nodes.append(node)

    def check_node_exist(self, node: DFDNode) -> bool:
        for n in self.nodes:
            if n.name == node.name:
                return True
        return False
    