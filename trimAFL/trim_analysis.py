import r2pipe
import logging
from .utils import *
l = logging.getLogger('trimAFL.analyses')

FuncName_Blacklist = set(
    ['frame_dummy',
     '__do_global_dtors_aux',
     '_dl_relocate_static_pie',
     'register_tm_clones',
     'deregister_tm_clones',
     '_start',
     '__cxa_finalize',
     '__stack_chk_fail',
     '_init',
     '__libc_start_main',
     '__libc_csu_init',
     '_fini'
    ])

NOTRIM_NODES = [
    "magma_log",
    "__afl",
    "LLVM",
    "__sanitizer",
    "_GLOBAL__",
    "__clang"
]


def uptrace_node(proj, cfg, t_node, pred_nodes, ret_func_addr=None, pre_pred=None):
    l.debug("Trace up %s\tfrom %s" % (t_node, pre_pred))
    if t_node.block is None:
        return pred_nodes
    t_addr = t_node.block.addr
    # Nodes to analyze later in the loop 
    new_predecessors = set()
    new_predecessors.add(t_node)
    while len(new_predecessors) != 0:
        pred = new_predecessors.pop()
        if pred.block is None or \
           pred.addr in pred_nodes:
            continue
        else:
            pred_nodes[pred.addr] = pred
        # Special case for un-resolved function predecessors
        # Jump directly to the predecessor ahead, if the predecessor ends with call
        cur_predecessors = list(cfg.model.get_predecessors(pred))
        if len(cur_predecessors) == 0:
            new_next_pred = search_pre_node(cfg, pred)
            if new_next_pred is not None and \
               new_next_pred.function_address == pred.function_address and \
               new_next_pred.addr not in pred_nodes:
                _, jump_kind = new_next_pred.successors_and_jumpkinds()[0]
                if jump_kind == "Ijk_Call":
                    new_predecessors.add(new_next_pred)
            continue
        for next_node, jumpkind in cfg.model.get_predecessors_and_jumpkinds(pred):
            # Nodes inside this function, nothing special
            if jumpkind == 'Ijk_Boring':
                if next_node is not None and\
                   next_node not in new_predecessors and \
                   next_node.block.addr not in pred_nodes:
                    new_predecessors.add(next_node)
            # Other function f returns here, indicates call by this function earlier
            # Trace up to f,
            #   Determine the block calling f by Ret-block.addr - 5
            elif jumpkind == 'Ijk_Ret':
                if next_node is not None and next_node.block is not None:
                    # Trace up the function only if node.block is not None
                    # node.block is None when calling linked lib (I guess)
                    uptrace_node(proj, cfg, next_node, pred_nodes, pred.function_address, pred)
                new_next_pred = search_pre_node(cfg, pred)
                if new_next_pred is not None and \
                   new_next_pred.function_address == pred.function_address and \
                   new_next_pred.addr not in pred_nodes:
                    new_predecessors.add(new_next_pred)
            # Do nothing when returning to the caller function
            # Except if no ret_func_addr (Tracing from middle of the function, don't know
            #    who is the caller)
            elif jumpkind == 'Ijk_Call':
                if ret_func_addr is None:
                    if next_node is None:
                        continue
                    new_predecessors.add(next_node)
                else:
                    continue
                continue
            else:
                raise Exception("Unknown CFG edge kind")
    l.debug("Finish %s\tfrom %s" % (t_node, pre_pred))
    return pred_nodes


def downtrace_node(proj, cfg, t_node, succ_nodes, cg_pred_addr_pairs, ret_func_addr=None, pre_succ=None):
    l.debug("Trace down %s\tfrom %s" % (t_node, pre_succ))
    if t_node.block is None:
        return succ_nodes
    t_addr = t_node.block.addr
    # Nodes to analyze later in the loop 
    new_successors = set()
    new_successors.add(t_node)
    while len(new_successors) != 0:
        succ = new_successors.pop()
        if succ.block is None or \
           succ.addr in succ_nodes:
            continue
        else:
            succ_nodes[succ.addr] = succ

        for next_node, jumpkind in cfg.model.get_successors_and_jumpkinds(succ):
            # Nodes inside this function, nothing special
            if jumpkind == 'Ijk_Boring':
                if next_node is None or next_node.block is None:
                    continue
                if next_node not in new_successors and \
                   next_node.addr not in succ_nodes:
                    new_successors.add(next_node)
            # Do nothing when returning to the caller function
            # Except if no ret_func_addr (Tracing from middle of the function, don't know
            #    who is the caller)
            elif jumpkind == 'Ijk_Ret':
                if ret_func_addr is None:
                    if next_node is None:
                        continue
                    new_successors.add(next_node)
                    """
                    for (pred_addr, succ_addr) in cg_pred_addr_pairs:
                        if succ_addr == succ.function_address and \
                           pred_addr == next_node.function_address:
                            new_successors.add(next_node)
                            break
                    """
                else:
                    continue

            # Determine the returning block Call-block.addr + 5
            elif jumpkind == 'Ijk_Call':
                if next_node is not None and next_node.block is not None:
                    # Trace down the function only if node.block is not None
                    # node.block is None when calling linked lib (I guess)
                    downtrace_node(proj, cfg, next_node, succ_nodes, cg_pred_addr_pairs, succ.function_address, succ)
                new_next_succ = search_next_node(cfg, succ)
                if new_next_succ is not None and \
                   new_next_succ.function_address == succ.function_address and \
                   new_next_succ.addr not in succ_nodes:
                    new_successors.add(new_next_succ)

            else:
                raise Exception("Unknown CFG edge kind")
    l.debug("Finish %s\tfrom %s" % (t_node, pre_succ))
    return succ_nodes


def _uptrace_cg(cfg, cg, t_addr):
    cg_pred_addrs = []
    next_addrs = [t_addr]
    done_addrs = set()
    while len(next_addrs) != 0:
        addr = next_addrs.pop()
        if addr in done_addrs:
            continue
        else:
            done_addrs.add(addr)
        for pred in cg.predecessors(addr):
            node = cfg.model.get_node(pred)
            if node.name in FuncName_Blacklist:
                continue
            pair = (pred, addr)
            if pair in cg_pred_addrs:
                continue
            cg_pred_addrs.append(pair)
            if pred not in done_addrs:
                next_addrs.append(pred)
    return cg_pred_addrs


def _downtrace_cg(cfg, cg, t_addr):
    cg_succ_addrs = []
    next_addrs = [t_addr]
    done_addrs = set()
    while len(next_addrs) != 0:
        addr = next_addrs.pop()
        if addr in done_addrs:
            continue
        else:
            done_addrs.add(addr)
        for succ in cg.successors(addr):
            node = cfg.model.get_node(succ)
            pair = (addr, succ)
            if pair in cg_succ_addrs:
                continue
            cg_succ_addrs.append(pair)
            if succ not in done_addrs:
                next_addrs.append(succ)
    return cg_succ_addrs


def _get_target_pred_succ_nodes(proj, cfg, cg, t_addr, target_nodes, pred_nodes, succ_nodes, pred_addr_pairs=None):
    t_node = search_node_by_addr(cfg, t_addr)
    if t_node is None:
        return ()
    if t_addr in target_nodes:
        return ()

    # A list of pred-succ pair in function callgraph
    if pred_addr_pairs is None:
        cg_pred_addr_pairs = _uptrace_cg(cfg, cg, t_addr)
    else:
        cg_pred_addr_pairs = pred_addr_pairs

    target_nodes[t_node.addr] = t_node
    l.info("Targeting 0x%08x in block %s" % (t_addr, t_node))

    # Put all predessors into pred_nodes
    # With the notion of context sensitivity
    l.info("Collecting Predcessors...")
    uptrace_node(proj, cfg, t_node, pred_nodes, None, None)

    # TODO: 
    #   Currently assume the list is in order from target->entry
    #   Find the first pair with pred not in & succ in, trace up from there
    for (pred, succ) in cg_pred_addr_pairs:
        # Check if all pairs are already included in pred_nodes
        # If not, uptrace from the caller of succ
        if pred not in pred_nodes and succ in pred_nodes:
            node = pred_nodes[succ]
            for next_node, jumpkind in node.predecessors_and_jumpkinds():
                if jumpkind == 'Ijk_Call' and next_node.function_address == pred:
                    l.debug("Continue to uptrace from %s to %s" % (node, next_node))
                    uptrace_node(proj, cfg, next_node, pred_nodes, None, node)

    # Put all successors into succ_nodes
    # Similiar implement as pred_nodes
    l.info("Collecting Successors...")
    downtrace_node(proj, cfg, t_node, succ_nodes, cg_pred_addr_pairs, None, None)

    return target_nodes, pred_nodes, succ_nodes


def _name_no_trim(name):
    for n in NOTRIM_NODES:
        if n in name:
            return True
    return False


def _get_trim_nodes(target_nodes, pred_nodes, succ_nodes):
    l.info("Filtering out trim-nodes...")
    trim_nodes = {}
    pred_successors = set() 
    for node in pred_nodes.values():
        for succ_node, jumpkind in node.successors_and_jumpkinds():
            if jumpkind != 'Ijk_Ret':
                pred_successors.add(succ_node)
    for node in pred_successors:
        addr = node.addr
        # Ignore these blocks to make AFL run
        if node.name is None or \
           node.block is None or \
           _name_no_trim(node.name):
            continue
        if addr not in pred_nodes and \
           addr not in target_nodes and \
           addr not in succ_nodes:
            trim_nodes[addr] = node

    return trim_nodes


def get_target_pred_succ_trim_nodes(proj, cfg, cg, t_addrs, pred_addr_pairs=None):
    pred_nodes = {}
    succ_nodes = {}
    target_nodes = {}
    for t_addr in t_addrs:
        ret = _get_target_pred_succ_nodes(proj, cfg, cg, t_addr, target_nodes, pred_nodes, succ_nodes, pred_addr_pairs)

    trim_nodes = _get_trim_nodes(target_nodes, pred_nodes, succ_nodes)

    return target_nodes, pred_nodes, succ_nodes, trim_nodes


def _insert_interrupt(r2, addr, cnt):
    r2.cmd('s ' + hex(addr))
    instr_data = r2.cmdj('pdj 1')[0]
    size = instr_data["size"]
    to_pend = size - 2
    if to_pend < 0:
        return cnt

    re_hex = "cd03"
    while to_pend > 0:
        if to_pend == 1:
            re_hex += "90"
            break
        elif to_pend == 2:
            re_hex += "6690"
            break
        elif to_pend == 3:
            re_hex += "0f1f00"
            break
        elif to_pend == 4:
            re_hex += "0f1f4000"
            break
        elif to_pend == 5:
            re_hex += "0f1f440000"
            break
        elif to_pend == 6:
            re_hex += "660f1f440000"
            break
        elif to_pend == 7:
            re_hex += "0f1f8000000000"
            break
        elif to_pend == 8:
            re_hex += "0f1f840000000000"
            break
        elif to_pend == 9:
            re_hex += "660f1f840000000000"
            break
        else:
            re_hex += "660f1f840000000000"
            to_pend -= 9

    rewrite = "wx " + re_hex
    l.info("Rewriting %s" % hex(addr))
    r2.cmd(rewrite)
    cnt += 1 
    return cnt


def insert_interrupt(binary, trim_addrs):
    r2 = r2pipe.open(binary, flags=['-w'])
    cnt = 0
    for addr in trim_addrs:
        cnt = _insert_interrupt(r2, addr, cnt)
    return cnt
