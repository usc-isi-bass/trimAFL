import r2pipe
import logging
l = logging.getLogger('trimAFL.analyses')

def get_target_pred_succ_trim_nodes(proj, cfg, t_addr):
    t_node = None
    for node in cfg.graph.nodes():
        if t_addr in node.instruction_addrs:
            t_node = node
            break

    target_nodes = {}
    target_nodes[t_node.addr] = t_node

    # Put all predessors into pred_nodes
    pred_nodes = {}
    predecessors = t_node.predecessors
    while len(predecessors) != 0:
        new_predecessors = []
        for node in predecessors:
            if node.block.addr in pred_nodes or node == t_node:
                continue
            pred_nodes[node.block.addr] = node
            for pre_node in node.predecessors:
                if pre_node.block is not None and pre_node.block.addr not in pred_nodes:
                    new_predecessors.append(pre_node)
        predecessors = new_predecessors

    # Put all successors into succ_nodes
    succ_nodes = {}
    successors = t_node.successors
    while len(successors) != 0:
        new_successors = []
        for node in successors:
            if node.block.addr in succ_nodes:
                continue
            succ_nodes[node.block.addr] = node
            for succ_node in node.successors:
                if succ_node.block is not None and succ_node.block.addr not in succ_nodes:
                    new_successors.append(succ_node)
        successors = new_successors

    trim_nodes = {}
    pred_successors = set() 
    for node in pred_nodes.values():
        for succ_node in node.successors:
            pred_successors.add(succ_node)
    for node in pred_successors:
        addr = node.addr
        if addr not in pred_nodes and \
           addr not in target_nodes and \
           addr not in succ_nodes:
            trim_nodes[addr] = node

    return target_nodes, pred_nodes, succ_nodes, trim_nodes


def _insert_interrupt(r2, addr):
    r2.cmd('s ' + hex(addr))
    instr_data = r2.cmdj('pdj 1')[0]
    size = instr_data["size"]
    to_pend = size - 2
    if to_pend < 0:
        return

    rewrite0 = "w0 %s" % size
    r2.cmd(rewrite0)

    rewrite = "wa int 0xf"
    for i in range(to_pend):
        rewrite += ";nop"

    l.info("Rewriting %s" % hex(addr))
    r2.cmd(rewrite)


def insert_interrupt(binary, trim_addrs):
    r2 = r2pipe.open(binary, flags=['-w'])
    for addr in trim_addrs:
        _insert_interrupt(r2, addr-0x400000)


