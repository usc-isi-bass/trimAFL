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
reach_func_set = set(block.function_address for block in reach_trace if block is not None and block.function_address is not None)

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

cfg_patch.patch_cfg_cg_with_caller_dict(proj, cfg_r, cg_r, patch_edges)

ep_node = cfg_r.model.get_any_node(proj.entry)

from networkx.algorithms.shortest_paths.generic import has_path
for node in cfg_r.model.nodes():
    if node is None:
        continue
    if node.name == target:
        print("CFG reachable: %s" % has_path(cfg_r.graph, ep_node, node))
        print("CG  reachable: %s" % has_path(cg_r, proj.entry, node.addr))


# Then, we look at the other trace
other_trace = cfg_patch.get_blocks_with_tracer(proj, cfg, binary, other_input)
other_seen = []

diff_loaded_blocks = []
diff_loaded_functions = []
diff_infunc_blocks = []
diff_unknown_blocks = []
for idx in range(len(other_trace)):
    block = other_trace[idx]
    if block in other_seen:
        continue
    else:
        other_seen.append(block)
    if block.addr not in reach_set:
        if block.function_address in reach_func_set:
            diff_infunc_blocks.append(block)
            continue
        pre_block = other_trace[idx-1]
        if pre_block in unreachable_callers:
            diff_loaded_blocks.append(block)
            diff_loaded_functions.append(block.function_address)
            continue
        if block.function_address in diff_loaded_functions:
            continue
        diff_unknown_blocks.append(block)
    else:
        continue

print("Diff loaded blocks:")
for block in diff_loaded_blocks:
    print(block.name)

print("\n========\n")

print("Diff infunc blocks:")
for block in diff_infunc_blocks:
    print(block.name)

print("\n========\n")

print("Diff other blocks:")
for block in diff_unknown_blocks:
    print(block.name)

print("\n========\n")
