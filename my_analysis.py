#!/usr/bin/env python3

import logging
logging.getLogger('angr').setLevel(logging.ERROR)
logging.getLogger('tracer').setLevel(logging.INFO)
logging.getLogger('pyvex').setLevel(logging.ERROR)
logging.getLogger('trimAFL').setLevel(logging.WARNING)

import sys
import os

from trimAFL import trim_analysis, cfg_patch
from trimAFL.core import * 
import tracer


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

def find_reachable_inputs(trim_proj, binary, input_dir, target, log_dir):
    done = []
    with open(f'{log_dir}/done.txt', "r") as fd:
        for line in fd.readlines():
            done.append(line.rstrip('\n'))

    for f in os.listdir(input_dir):
        input_f = "{}/{}".format(input_dir, f)
        if input_f in done:
            print(input_f + "  skip")
            continue
        print(input_f)

        blocks = get_blocks_with_tracer(trim_proj.project, trim_proj.cfg, binary, input_f)

        flag = False
        with open(f'{log_dir}/traces/{f}.trace', "w") as fd_b:
            for block in blocks:
                if block.name is not None:
                    fd_b.write(block.name + "\n")
                    if target in block.name and not flag:
                        flag = True
        if not flag:
            with open(f'{log_dir}/unreachable.txt', "a") as fd:
                fd.write(input_f + "\n")
        else:
            with open(f'{log_dir}/reachable.txt', "a") as fd:
                fd.write(input_f + "\n")

        with open(f'{log_dir}/done.txt', "a") as fd:
            fd.write(input_f + "\n")



binary = sys.argv[1]
input_dir = sys.argv[2]
target = sys.argv[3]
log_dir = sys.argv[4]

trim_proj = TrimAFL(binary, target, False)

find_reachable_inputs(trim_proj, binary, input_dir, target, log_dir)
