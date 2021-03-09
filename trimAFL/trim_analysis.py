import r2pipe
import logging
l = logging.getLogger('trimAFL.analyses')

def find_func_symbols(proj, sym):
    candidates = []
    for s in proj.loader.symbols:
        if sym == s.name:
            return [s]
        if sym in s.name:
            candidates.append(s)
    return candidates


def search_node_by_addr(proj, cfg, t_addr):
    t_node = None
    for node in cfg.graph.nodes():
        if t_addr in node.instruction_addrs:
            return node


# Keys: predecessors' addresses
# Values: this predecessor's children
def get_cg_pred_sib_addrs(proj, cg, t_addr):
    ret = {}
    ret[t_addr] = []
    new_preds = [addr for addr in cg.predecessors(t_addr)]

    while len(new_preds) != 0:
        addr = new_preds.pop()
        if addr not in ret:
            ret[addr] = [a for a in cg.successors(addr)]
            new_preds += [a for a in cg.predecessors(addr)]
    return ret


def get_cg_succ_addrs(proj, cg, t_addr):
    ret = [t_addr]
    new_preds = [addr for addr in cg.successors(t_addr)]

    while len(new_preds) != 0:
        addr = new_preds.pop()
        if addr not in ret:
            ret.append(addr)
            new_preds += [addr for addr in cg.successors(addr)]
    return ret

def _uptrace_node(t_node, cg, pred_nodes, ret_func_addr):
    if t_node.block is None:
        return pred_nodes, {}
    t_addr = t_node.block.addr
    next_preds = {}
    new_predecessors = [t_node]
    while len(new_predecessors) != 0:
        pred = new_predecessors.pop()
        if pred in pred_nodes:
            continue
        else:
            pred_nodes[pred.block.addr] = pred

        for next_node, jumpkind in pred.predecessors_and_jumpkinds():
            if jumpkind == 'Ijk_Boring':
                new_predecessors.append(next_node)
            elif jumpkind == 'Ijk_Ret':
                new_pred_nodes, new_next_preds = _uptrace_node(next_node, cg, pred_nodes, pred.function_address)
                pred_nodes.update(new_pred_nodes)
                new_predecessors += new_next_preds.values()
            elif jumpkind == 'Ijk_Call':
                if next_node.function_address == ret_func_addr:
                    next_preds[next_node.block.addr] = next_node
                else:
                    continue
            else:
                raise Exception("Unknown CFG edge kind")
    return pred_nodes, next_preds


def new_get_target_pred_succ_nodes(t_node, cg):
    t_addr = t_node.block.addr
    pred_nodes = {}
    new_predecessors = [t_node]
    while len(new_predecessors) != 0:
        pred = new_predecessors.pop()
        if pred.block.addr in pred_nodes:
            continue
        else:
            pred_nodes[pred.block.addr] = pred

        for next_node, jumpkind in pred.predecessors_and_jumpkinds():
            if jumpkind == 'Ijk_Boring':
                new_predecessors.append(next_node)
            elif jumpkind == 'Ijk_Ret':
                pred_nodes, next_preds = _uptrace_node(next_node, cg, pred_nodes, pred.function_address)
                new_predecessors += next_preds.values()
            elif jumpkind == 'Ijk_Call':
                new_predecessors.append(next_node)
            else:
                raise Exception("Unknown CFG edge kind")
    return pred_nodes


def _get_target_pred_succ_nodes(proj, cfg, t_addr, target_nodes, pred_nodes, succ_nodes):
    t_node = search_node_by_addr(proj, cfg, t_addr)

    if t_node is None:
        return ()

    if t_addr in target_nodes:
        return ()

    target_nodes[t_node.addr] = t_node
    l.info("Targeting 0x%08x in block 0x%08x" % (t_addr, t_node.addr))

    # Put all predessors into pred_nodes
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

    return target_nodes, pred_nodes, succ_nodes


def _get_trim_nodes(target_nodes, pred_nodes, succ_nodes):
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

    return trim_nodes


def get_target_pred_succ_trim_nodes(proj, cfg, t_addrs):
    pred_nodes = {}
    succ_nodes = {}
    target_nodes = {}
    for t_addr in t_addrs:
        ret = _get_target_pred_succ_nodes(proj, cfg, t_addr, target_nodes, pred_nodes, succ_nodes)
        if len(ret) != 0:
            target_blocks, pre_blocks, succ_blocks = ret

    trim_nodes = _get_trim_nodes(target_nodes, pred_nodes, succ_nodes)

    return target_nodes, pred_nodes, succ_nodes, trim_nodes


def _insert_interrupt(r2, addr, cnt):
    r2.cmd('s ' + hex(addr))
    instr_data = r2.cmdj('pdj 1')[0]
    size = instr_data["size"]
    to_pend = size - 2
    if to_pend < 0:
        return cnt

    rewrite0 = "w0 %s" % size
    r2.cmd(rewrite0)

    rewrite = "wa int 0x3"
    for i in range(to_pend):
        rewrite += ";nop"

    l.info("Rewriting %s" % hex(addr))
    r2.cmd(rewrite)
    cnt += 1 
    return cnt


def insert_interrupt(binary, trim_addrs):
    r2 = r2pipe.open(binary, flags=['-w'])
    cnt = 0
    for addr in trim_addrs:
        cnt = _insert_interrupt(r2, addr-0x400000, cnt)
    return cnt


