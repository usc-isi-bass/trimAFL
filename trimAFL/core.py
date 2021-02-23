import angr
from . import trim_analysis

class TrimAFL(object):
    def __init__(self, binary, target):
        self.binary = binary
        self.project = angr.Project(self.binary, load_options={'auto_load_libs': False})
        self.cfg = self.project.analyses.CFGFast(fail_fast=False, normalize=True, show_progressbar=True,
                                                 symbols=True, function_prologues=True, force_complete_scan=True,
                                                 collect_data_references=False, resolve_indirect_jumps=True)

        if target.startswith("0x"):
            target_addr = int(target.split("0x", 1)[1], 16)
            self.target_addr = target_addr
        else:
            t_symbols = trim_analysis.find_func_symbols(self.project, target)
            # FIXME: Use the first function found
            if len(t_symbols) == 0:
                return
            self.target_addr = t_symbols[0].rebased_addr


    def _reload_proj_and_cfg(self):
        self.project = angr.Project(self.binary, load_options={'auto_load_libs': False})
        self.cfg = self.project.analyses.CFGFast(fail_fast=False, normalize=True, show_progressbar=True,
                                                 symbols=True, function_prologues=True, force_complete_scan=True,
                                                 collect_data_references=False, resolve_indirect_jumps=True)

    def trim_binary(self):
        target_blocks, pre_blocks, succ_blocks, trim_blocks = trim_analysis.get_target_pred_succ_trim_nodes(self.project, self.cfg, self.target_addr)
        trim_analysis.insert_interrupt(self.binary, trim_blocks.keys())
        self._reload_proj_and_cfg()
