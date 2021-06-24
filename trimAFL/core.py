import angr
import os
import logging
l = logging.getLogger('trimAFL.core')
from . import trim_analysis
from .utils import *
from . import cfg_patch

class TrimAFL(object):
    def __init__(self, binary, target, use_file=False):
        self.binary = binary
        self.project = angr.Project(self.binary, load_options={'auto_load_libs': False, 'main_opts': {'base_addr': 0x0}})
        self.cfg = self.project.analyses.CFGFast(fail_fast=False, normalize=True,
                                                 symbols=True, function_prologues=True, force_complete_scan=True, show_progressbar=True,
                                                 data_references=False, resolve_indirect_jumps=True)

        self.target_addrs = []
        self.cg = self.cfg.functions.callgraph

        l.info("CFG size: %s blocks" % len(self.cfg.model.nodes()))

        if use_file:
            targets = []
            with open(target, "r") as fd:
                for line in fd.readlines():
                    targets.append(line.replace("\n", ""))
            for t in targets:
                l.debug("Target: %s" % t)
                self._init_target(t)
        else:
            self._init_target(target)

        if len(self.target_addrs) == 0:
            l.warn("No target found!")

        self.trim_count = 0


    def _init_target(self, target):
        if target.startswith("0x"):
            target_addr = int(target.split("0x", 1)[1], 16)
            self.target_addrs.append(target_addr)
        else:
            t_symbols = find_func_symbols(self.project, target)
            if len(t_symbols) == 0:
                return
            self.target_addrs += [symbol.rebased_addr for symbol in t_symbols]


    def _reload_proj_and_cfg(self):
        self.project = angr.Project(self.binary, load_options={'auto_load_libs': False})
        self.cfg = self.project.analyses.CFGFast(fail_fast=False, normalize=True,
                                                 symbols=True, function_prologues=True, force_complete_scan=True,
                                                 collect_data_references=False, resolve_indirect_jumps=True)


    def demo(self):
        t_node = search_node_by_addr(self.cfg, self.target_addrs[0])
        e_node = self.cfg.model.get_node(self.project.entry)

        target_blocks, pred_blocks, succ_blocks, trim_blocks = trim_analysis.get_target_pred_succ_trim_nodes(self.project, self.cfg, self.cg, self.target_addrs)

        """
        for b in pred_blocks.values():
            if len(b.successors) > 1:
                print(b)
        """
        print("Blocks to be trimmed:")
        for addr, block in trim_blocks.items():
            print(block)


    def trim_binary(self, cfg=None, cg=None):
        if cfg is None or cg is None:
            cfg = self.cfg
            cg = self.cg
        target_blocks, pred_blocks, succ_blocks, trim_blocks = trim_analysis.get_target_pred_succ_trim_nodes(self.project, cfg, cg, self.target_addrs)
        l.info("----------- Blocks to be trimmed -----------")
        for addr, block in trim_blocks.items():
            l.info(block)
        l.info("-----------    Start Trimming    -----------")
        self.trim_count = trim_analysis.insert_interrupt(self.binary, trim_blocks.keys())
        # self._reload_proj_and_cfg()
        print("Trim-number: %s" % self.trim_count)
        return self.trim_count


    def new_cfg_cg_with_seeds(self, seed_dir):
        cfg_r = self.cfg.copy()
        cg_r= self.cg.copy()

        unreachable_callers = cfg_patch.find_unresolved_callers(self.project, cfg_r)
        patch_edges = {}

        for f in os.listdir(seed_dir):
            input_f = "%s/%s" % (seed_dir, f)
            reach_trace = cfg_patch.get_blocks_with_tracer(self.project, cfg_r, self.binary, input_f)

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

        cfg_patch.patch_cfg_cg_with_caller_dict(self.project, cfg_r, cg_r, patch_edges)
        return cfg_r, cg_r

