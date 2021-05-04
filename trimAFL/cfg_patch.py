import tracer
from .utils import *

import logging
log = logging.getLogger('trimAFL.cfg_patch')

def get_blocks_with_tracer(cfg, binary, argv):
    r = tracer.qemu_runner.QEMURunner(binary, input=b'', argv=argv)
    block_trace = []
    for addr in t.dynamic_trace():
        if r.rebase:
            new_addr = addr - r.base_addr
        node = cfg.model.get_node(new_addr)
        if node is not None:
            block_trace.append(node)
    return block_trace


def get_blocks_with_symstate(cfg, state):
    block_trace = []
    for addr in state.history.bbl_addrs:
        node = cfg.model.get_node(addr)
        if node is not None:
            block_trace.append(node)
    return block_trace


def find_unresolved_callers(proj, cfg):
    unresolved_callers = set()
    for node in cfg.model.nodes():
        if len(node.successors) == 1 and \
           node.successors[0].name == "UnresolvableCallTarget" and \
           node.name is not None and not node.name.startswith("_"):
            # TODO: is there a better way of blacklisting?
            unresolved_callers.add(node)
            log.debug("Unresolvable call in %s" % node)
    return unresolved_callers


def _replace_unresolved_callees(cfg, cg, caller, callee, ret_node):
    # Remove UnresolvableCallTarget, if still exists
    unresolve_node = None
    for node in caller.successors:
        if node.name is not None and node.name == "UnresolvableCallTarget":
            unresolve_node = node
            break
    if unresolve_node is not None:
        cfg.graph.remove_edge(caller, unresolve_node)
        cg.remove_edge(caller.function_address, unresolve_node.addr)
    # Add the callee to cfg and cg
    cfg.graph.add_edge(caller, callee, jumpkind="Ijk_Call")
    cg.add_edge(caller.function_address, callee.function_address)
    # Bridge the returning node and the ret blocks of the called function
    callee_end_nodes = find_function_end_nodes(callee)
    for node in callee_end_nodes:
        cfg.graph.add_edge(node, ret_node, jumpkind="Ijk_Ret")


def patch_cfg_cg_with_blocktrace(proj, cfg, cg, unresolved_callers, block_trace):
    proceeded_addr_pairs = set()
    for caller in unresolved_callers:
        if caller not in block_trace:
            continue
        caller_idx = 0
        ret_node = search_node_by_addr(proj, cfg, caller.block.instruction_addrs[-1]+5)
        for i in range(block_trace.count(caller)):
            caller_idx = block_trace.index(caller, caller_idx)
            caller_idx += 1
            callee = block_trace[caller_idx]
            if (caller.addr, callee.addr) not in proceeded_addr_pairs:
                _replace_unresolved_callees(cfg, cg, caller, callee, ret_node)
                proceeded_addr_pairs.add((caller.addr, callee.addr))

