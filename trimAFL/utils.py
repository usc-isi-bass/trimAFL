
def find_func_symbols(proj, sym):
    if sym.count("::") == 1:
        classname, funcname = sym.split("::")
        return find_cpp_func_symbols(proj, classname, funcname)
    candidates = []
    for s in proj.loader.symbols:
        if sym == s.name:
            return [s]
        if sym in s.name:
            candidates.append(s)
    return candidates

def find_cpp_func_symbols(proj, classname, funcname):
    candidates = []
    for s in proj.loader.symbols:
        if classname == funcname:
            name = s.name
            if name.count(classname) == 2:
                return [s]
            else:
                continue
        if classname in s.name and \
           funcname in s.name:
            name = s.name
            found = name.find(classname)
            if name[found-1].isdigit() and \
               name[found+len(classname)].isdigit():
                return [s]
            candidates.append(s)
    return candidates


def search_node_by_addr(cfg, t_addr):
    for node in cfg.model.nodes():
        if node is not None and t_addr in node.instruction_addrs:
            return node


# Return the node before cur_node_addr
#   search for the caller node of this ret node
def search_pre_node(cfg, cur_node):
    cur_node_addr = cur_node.addr
    for i in range(4, 10):
        pred = search_node_by_addr(cfg, cur_node_addr - i)
        if pred is not None:
            return pred
    return None


# Return the next node after cur_node_addr
#   search for the ret node of this caller node
def search_next_node(cfg, cur_node):
    if cur_node.block is None:
        return None
    cur_block_size = cur_node.block.size
    next_node_addr = cur_node.addr + cur_block_size
    for i in range(5):
        succ = search_node_by_addr(cfg, next_node_addr + i)
        if succ is not None:
            return succ
    return None


# A more formal way of determining node reachablility
def target_node_reachable(proj, cfg, entry_node, t_node, seen_nodes=set()):
    new_successors = set()
    new_successors.add(entry_node)
    while len(new_successors) != 0:
        succ = new_successors.pop()
        if succ == t_node:
            return True
        if succ in seen_nodes:
            continue
        else:
            seen_nodes.add(succ)
        for next_node, jumpkind in succ.successors_and_jumpkinds():
            if next_node == t_node:
                return True
            if jumpkind == 'Ijk_Boring':
                if next_node not in new_successors and \
                   next_node not in seen_nodes:
                    new_successors.add(next_node)
            elif jumpkind == 'Ijk_Ret':
                continue
            elif jumpkind == 'Ijk_Call':
                ret = target_node_reachable(proj, cfg, next_node, t_node, seen_nodes)
                if ret:
                    return True
                if succ.block is None:
                    continue
                new_next_succ = search_node_by_addr(cfg, succ.block.instruction_addrs[-1]+5)
                if new_next_succ is not None and \
                   new_next_succ.function_address == succ.function_address and \
                   new_next_succ not in seen_nodes:
                    new_successors.add(new_next_succ)
    return False


def find_function_end_nodes(proj, cfg, e_node):
    end_nodes = set()
    seen_nodes = set()
    new_successors = set()
    new_successors.add(e_node)
    cur_func_name = e_node.name
    while len(new_successors) != 0:
        succ = new_successors.pop()
        if succ in seen_nodes:
            continue
        else:
            seen_nodes.add(succ)

        if len(cfg.model.get_successors(succ)) == 0:
            end_nodes.add(succ)

        for next_node, jumpkind in cfg.model.get_successors_and_jumpkinds(succ):
            if jumpkind == 'Ijk_Boring':
                if next_node.block is None:
                    continue
                if next_node not in new_successors and \
                   next_node not in seen_nodes:
                    new_successors.add(next_node)
            elif jumpkind == 'Ijk_Ret':
                end_nodes.add(next_node)
            elif jumpkind == 'Ijk_Call':
                new_next_succ = search_node_by_addr(cfg, succ.block.instruction_addrs[-1]+5)
                if new_next_succ is not None and \
                   new_next_succ.function_address == succ.function_address and \
                   new_next_succ not in seen_nodes:
                    new_successors.add(new_next_succ)
            else:
                raise Exception("Unknown CFG edge kind")
    return end_nodes

# new playground

