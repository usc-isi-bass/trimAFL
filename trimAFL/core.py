import angr
import logging
l = logging.getLogger('trimAFL.core')
from . import trim_analysis

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
            t_symbols = trim_analysis.find_func_symbols(self.project, target)
            if len(t_symbols) == 0:
                return
            self.target_addrs += [symbol.rebased_addr for symbol in t_symbols]


    def _reload_proj_and_cfg(self):
        self.project = angr.Project(self.binary, load_options={'auto_load_libs': False})
        self.cfg = self.project.analyses.CFGFast(fail_fast=False, normalize=True,
                                                 symbols=True, function_prologues=True, force_complete_scan=True,
                                                 collect_data_references=False, resolve_indirect_jumps=True)


    def demo(self):
        target_blocks, pred_blocks, succ_blocks, trim_blocks = trim_analysis.get_target_pred_succ_trim_nodes(self.project, self.cfg, self.cg, self.target_addrs)
        print("Blocks to be trimmed:")
        for addr, block in trim_blocks.items():
            print(block)


    def trim_binary(self):
        target_blocks, pred_blocks, succ_blocks, trim_blocks = trim_analysis.get_target_pred_succ_trim_nodes(self.project, self.cfg, self.cg, self.target_addrs)
        l.info("----------- Blocks to be trimmed -----------")
        for addr, block in trim_blocks.items():
            l.info(block)
        l.info("-----------    Start Trimming    -----------")
        self.trim_count = trim_analysis.insert_interrupt(self.binary, trim_blocks.keys())
        # self._reload_proj_and_cfg()
        print("Trim-number: %s" % self.trim_count)
        return self.trim_count

