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


def _uptrace_node(t_node, pred_connections, ret_func_addr=None, pre_pred=None):
    l.debug("Trace up %s\tfrom %s" % (t_node, pre_pred))
    if t_node.block is None:
        return {}, {}
    t_addr = t_node.block.addr
    # Predecessors collected from this function (including inner calls)
    pred_nodes = {}
    # Predecessors calling this function, return to the caller(parent)
    next_preds = {}
    # Nodes to analyze later in the loop 
    new_predecessors = set()
    new_predecessors.add(t_node)
    while len(new_predecessors) != 0:
        pred = new_predecessors.pop()
        if pred.block is None or \
           pred in pred_nodes:
            continue
        else:
            pred_nodes[pred.block.addr] = pred
        for next_node, jumpkind in pred.predecessors_and_jumpkinds():
            if next_node.block is None:
                continue
            # Nodes inside this function, nothing special
            if jumpkind == 'Ijk_Boring':
                if next_node not in new_predecessors and \
                   next_node.block.addr not in pred_nodes:
                    new_predecessors.add(next_node)
            # Other function f returns here, indicates call by this function earlier
            # Trace up to f,
            #   continues with the returned next_preds (Nodes calling f)
            elif jumpkind == 'Ijk_Ret':
                connection = (next_node.function_address, pred.function_address)
                if connection in pred_connections:
                    continue
                else:
                    pred_connections.append(connection)
                new_pred_nodes, new_next_preds = _uptrace_node(next_node, pred_connections, pred.function_address, pred)
                new_predecessors.update(new_next_preds.values())
                pred_nodes.update(new_pred_nodes)
            # Returning to the caller(parent) calling this function
            # Only go back to THE caller (be context-sensitive)
            elif jumpkind == 'Ijk_Call':
                if ret_func_addr is None:
                    new_predecessors.add(next_node)
                else:
                    if next_node.function_address == ret_func_addr:
                        next_preds[next_node.block.addr] = next_node
                    else:
                        continue
            else:
                raise Exception("Unknown CFG edge kind")
    l.debug("Finish %s\tfrom %s" % (t_node, pre_pred))
    return pred_nodes, next_preds


def _downtrace_node(t_node, succ_connections, ret_func_addr=None, pre_pred=None):
    l.debug("Trace down %s\tfrom %s" % (t_node, pre_pred))
    if t_node.block is None:
        return {}, {}
    t_addr = t_node.block.addr
    succ_nodes = {}
    next_succs = {}
    new_successors = [t_node]
    while len(new_successors) != 0:
        succ = new_successors.pop()
        if succ.block is None or succ.block.addr in succ_nodes:
            continue
        else:
            succ_nodes[succ.block.addr] = succ
        for next_node, jumpkind in succ.successors_and_jumpkinds():
            if jumpkind == 'Ijk_Boring':
                new_successors.append(next_node)
            elif jumpkind == 'Ijk_Ret':
                if ret_func_addr is None:
                    new_successors.append(next_node)
                else:
                    if next_node.function_address == ret_func_addr:
                        next_succs[next_node.block.addr] = next_node
                    else:
                        continue
            elif jumpkind == 'Ijk_Call':
                connection = (next_node.function_address, succ.function_address)
                if connection in succ_connections:
                    continue
                else:
                    succ_connections.append(connection)
                new_succ_nodes, new_next_succs = _downtrace_node(next_node, succ_connections, succ.function_address, succ)
                new_successors += new_next_succs.values()
                succ_nodes.update(new_succ_nodes)
            else:
                raise Exception("Unknown CFG edge kind")
    return succ_nodes, next_succs


def _get_target_pred_succ_nodes(proj, cfg, t_addr, target_nodes, pred_nodes, succ_nodes):
    t_node = search_node_by_addr(proj, cfg, t_addr)
    if t_node is None:
        return ()
    if t_addr in target_nodes:
        return ()
    target_nodes[t_node.addr] = t_node
    l.info("Targeting 0x%08x in block 0x%08x" % (t_addr, t_node.addr))

    # Put all predessors into pred_nodes
    # With the notion of context sensitivity
    pred_connections = []
    l.info("Collecting Predcessors...")
    new_pred_nodes,_ = _uptrace_node(t_node, pred_connections, None, None)
    pred_nodes.update(new_pred_nodes)

    # Put all successors into succ_nodes
    # Similiar implement as pred_nodes
    succ_connections = []
    l.info("Collecting Successors...")
    new_succ_nodes,_ = _downtrace_node(t_node, succ_connections, None, None)
    succ_nodes.update(new_succ_nodes)

    return target_nodes, pred_nodes, succ_nodes


def _old_get_target_pred_succ_nodes(proj, cfg, t_addr, target_nodes, pred_nodes, succ_nodes):
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
    l.info("Filtering out trim-nodes...")
    trim_nodes = {}
    pred_successors = set() 
    for node in pred_nodes.values():
        for succ_node in node.successors:
            pred_successors.add(succ_node)
    for node in pred_successors:
        addr = node.addr
        # Ignore these blocks to make AFL run
        if node.name is None or \
           node.name.startswith("__afl"):
            continue
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


