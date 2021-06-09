#!/usr/bin/env python3

import logging
logging.getLogger('angr').setLevel(logging.ERROR)
logging.getLogger('tracer').setLevel(logging.ERROR)
logging.getLogger('pyvex').setLevel(logging.ERROR)
logging.getLogger('trimAFL').setLevel(logging.WARNING)
logging.getLogger('trimAFL.cfg_patch').setLevel(logging.INFO)

import sys
import os

from trimAFL import trim_analysis, cfg_patch
from trimAFL.core import * 
import tracer



base_dir = "/home/weicheng/directed_fuzzer/magma_tar/afl-libtiff-tiff_read_rgba_fuzzer/"
binary = "./analysis_results/tiff_read_rgba_fuzzer"
target = "PixarLogDecode"
reach_input = "./analysis_results/reach_paths/PixarLogDecode/input"
other_input = "./analysis_results/reach_paths/LZWDecode/input"

trim_proj = TrimAFL(binary, target, False)

proj = trim_proj.project
cfg = trim_proj.cfg
cg = trim_proj.cg

reach_trace = cfg_patch.get_blocks_with_tracer(proj, cfg, binary, reach_input)
reach_set = set(block.addr for block in reach_trace if block is not None)

#other_trace = get_blocks_with_tracer(proj, cfg, binary, other_input)

# Complete a cfg with the reach_trace
# record all patched unresolvable caller
# Check the difference resolving blocks in other_trace
cfg_r = cfg.copy()
cg_r= cg.copy()

unreachable_callers = cfg_patch.find_unresolved_callers(proj, cfg_r)

patch_edges = {}
for caller in unreachable_callers:
    if caller not in reach_trace:
        continue
    caller_idx = 0
    callee_addresses = set()
    for i in range(reach_trace.count(caller)):
        caller_idx = reach_trace.index(caller, caller_idx)
        caller_idx += 1
        callee = reach_trace[caller_idx]
        callee_addresses.add(callee.addr)
    patch_edges[caller.addr] = callee_addresses

cfg_patch.patch_cfg_cg_with_caller_dict(proj, cfg_r, cg, patch_edges)

ep_node = cfg_r.model.get_any_node(proj.entry)

from networkx.algorithms.shortest_paths.generic import has_path
for node in cfg_r.model.nodes():
    if node is None:
        continue
    if node.name == target:
        print(has_path(cfg_r.graph, ep_node, node))
        print(has_path(cg_r, proj.entry, node.addr))
        # Both False, gg

# See which exact blocks are still unreached in reach_set
seen_names = set()
for block_addr in reach_set:
    node = cfg_r.model.get_any_node(block_addr)
    if node is None or node.name is None:
        continue
    if has_path(cfg.graph, ep_node, node):
        continue
    name = node.name.split("+")[0]
    if name in seen_names:
        continue
    else:
        seen_names.add(name)
    if name.startswith("_"):
        continue
    print(name)
    node = cfg.model.get_any_node(node.function_address)
    print(has_path(cfg_r.graph, ep_node, node))
    print(has_path(cg_r, proj.entry, node.function_address))
    print()



