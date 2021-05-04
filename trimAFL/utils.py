
def find_func_symbols(proj, sym):
    candidates = []
    for s in proj.loader.symbols:
        if sym == s.name:
            return [s]
        if sym in s.name:
            candidates.append(s)
    return candidates


def search_node_by_addr(proj, cfg, t_addr):
    for node in cfg.model.nodes():
        if t_addr in node.instruction_addrs:
            return node


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

        if len(succ.successors) == 0:
            end_nodes.add(succ)

        for next_node, jumpkind in succ.successors_and_jumpkinds():
            if jumpkind == 'Ijk_Boring':
                if next_node.block is None:
                    continue
                if next_node not in new_successors and \
                   next_node not in seen_nodes:
                    new_successors.add(next_node)
            elif jumpkind == 'Ijk_Ret':
                end_nodes.add(next_node)
            elif jumpkind == 'Ijk_Call':
                new_next_succ = search_node_by_addr(proj, cfg, succ.block.instruction_addrs[-1]+5)
                if new_next_succ is not None and \
                   new_next_succ.function_address == succ.function_address and \
                   new_next_succ not in seen_nodes:
                    new_successors.add(new_next_succ)
            else:
                raise Exception("Unknown CFG edge kind")
    return end_nodes

