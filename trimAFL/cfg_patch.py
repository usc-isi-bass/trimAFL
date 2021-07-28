import tracer
from .utils import *
from networkx.algorithms.shortest_paths.generic import has_path

import logging
log = logging.getLogger('trimAFL.cfg_patch')

def get_blocks_with_tracer(proj, cfg, binary, argv):
    r = tracer.qemu_runner.QEMURunner(binary, input=b'', argv=[binary, argv], project=proj)
    block_trace = []
    for addr in r.trace:
        if r.rebase:
            new_addr = addr - r.base_addr
            node = cfg.model.get_node(new_addr)
        else:
            node = cfg.model.get_node(addr)
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
        successors = cfg.model.get_successors(node)
        if len(successors) == 1 and \
           successors[0].name == "UnresolvableCallTarget" and \
           node.name is not None:
            unresolved_callers.add(node)
            log.debug("Unresolvable call in %s" % node)
    return unresolved_callers


# Legacy
def _replace_unresolved_callees(proj, cfg, cg, caller, callee, ret_node):
    # Remove UnresolvableCallTarget, if still exists
    unresolve_node = None
    for node in cfg.model.get_successors(caller):
        if node.name is not None and node.name == "UnresolvableCallTarget":
            unresolve_node = node
            break
    if unresolve_node is not None:
        cfg.graph.remove_edge(caller, unresolve_node)
        cg.remove_edge(caller.function_address, unresolve_node.addr)
        log.debug("Remove %s from %s" % (unresolve_node, caller))
    # Add the callee to cfg and cg
    cfg.graph.add_edge(caller, callee, jumpkind="Ijk_Call")
    cg.add_edge(caller.function_address, callee.function_address)
    log.debug("Add %s to %s" % (callee, caller))
    # Bridge the returning node and the ret blocks of the called function
    callee_end_nodes = find_function_end_nodes(proj, cfg, callee)
    for node in callee_end_nodes:
        log.debug("Ret %s to %s" % (callee, ret_node))
        cfg.graph.add_edge(node, ret_node, jumpkind="Ijk_Ret")


# Legacy
def patch_cfg_cg_with_blocktrace(proj, cfg, cg, unresolved_callers, block_trace):
    proceeded_addr_pairs = set()
    for caller in unresolved_callers:
        if caller not in block_trace:
            continue
        caller_idx = 0
        ret_node = search_node_by_addr(cfg, caller.block.instruction_addrs[-1]+5)
        for i in range(block_trace.count(caller)):
            caller_idx = block_trace.index(caller, caller_idx)
            caller_idx += 1
            callee = block_trace[caller_idx]
            if (caller.addr, callee.addr) not in proceeded_addr_pairs:
                _replace_unresolved_callees(proj, cfg, cg, caller, callee, ret_node)
                proceeded_addr_pairs.add((caller.addr, callee.addr))


# new playground

# Not using for now
def find_reachable_unresolved_callers(proj, cfg, cg):
    unresolved_callers = set()
    # Cg could be more precise on determining reachability
    ep_func = cfg.model.get_any_node(proj.entry).function_address
    for node in cfg.model.nodes():
        # Since cfg is copied, need to get successors this way then node.successors
        successors = cfg.model.get_successors(node)
        if len(successors) == 1 and \
           successors[0].name == "UnresolvableCallTarget" and \
           node.name is not None and not node.name.startswith("_"):
            # TODO: is there a better way of blacklisting?
            if has_path(cg, ep_func, node.function_address):
                unresolved_callers.add(node)
                log.debug("Unresolvable call in %s" % node)
    return unresolved_callers


def patch_cfg_cg_with_caller_dict(proj, cfg, cg, edge_addr_dict):
    for caller_addr, callee_addrs in edge_addr_dict.items():
        caller = cfg.model.get_any_node(caller_addr)
        if caller is None:
            continue
        ret_node = search_next_node(cfg, caller)
        if ret_node is None:
            continue

        # Remove UnresolvableCallTarget, if still exists
        unresolve_node = None
        for node in cfg.model.get_successors(caller):
            if node.name is not None and node.name == "UnresolvableCallTarget":
                unresolve_node = node
                break
        if unresolve_node is not None:
            if cfg.graph.has_edge(caller, unresolve_node):
                cfg.graph.remove_edge(caller, unresolve_node)
            if cg.has_edge(caller.function_address, unresolve_node.addr):
                cg.remove_edge(caller.function_address, unresolve_node.addr)
            log.debug("Remove %s from %s" % (unresolve_node, caller))

        for callee_addr in callee_addrs:
            callee = cfg.model.get_any_node(callee_addr)
            if callee is None:
                continue
            _add_callee(proj, cfg, cg, caller, callee, ret_node)


def _add_callee(proj, cfg, cg, caller, callee, ret_node):
    # Add the callee to cfg and cg
    cfg.graph.add_edge(caller, callee, jumpkind="Ijk_Call")
    cg.add_edge(caller.function_address, callee.function_address)
    log.debug("Add %s to %s" % (callee, caller))
    # Bridge the returning node and the ret blocks of the called function
    callee_end_nodes = find_function_end_nodes(proj, cfg, callee)
    for node in callee_end_nodes:
        log.debug("Ret %s to %s" % (callee, ret_node))
        cfg.graph.add_edge(node, ret_node, jumpkind="Ijk_Ret")


def find_calleeaddrs_from_trace(caller_block, trace):
    pass

