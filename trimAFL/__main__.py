import logging
logging.getLogger('angr.analyses').setLevel(logging.WARNING)
logging.getLogger('trimAFL').setLevel(logging.INFO)
l = logging.getLogger('trimAFL.main')

import os
from optparse import OptionParser

from .core import TrimAFL
from .trim_analysis import search_node_by_addr



def main():
    usage = "usage: %prog [options] <binary> <target func/addr>"
    parser = OptionParser(usage=usage)
    parser.add_option("-d", "--display-only", dest="display", action="store_true",
                      help="display blocks to trim")
    parser.add_option("-r", "--rewrite", dest="rewrite", action="store_true",
                      help="rewrite binary")
    parser.add_option("-f", "--target-file", dest="use_file", action="store_true",
                      help="import file for targets")

    (options, args) = parser.parse_args()
    if len(args) != 2 or not os.path.exists(args[0]):
        parser.error("Missing binary or target")
        exit(1)

    if options.use_file:
        if not os.path.exists(args[1]):
            parser.error("Missing file for targets")
            exit(1)

    proj = TrimAFL(args[0], args[1], options.use_file)
    if options.display:
        for addr in proj.target_addrs:
            l.info("Target 0x%08x: %s" % (addr, search_node_by_addr(proj.project, proj.cfg, addr)))
        proj.demo()
    elif options.rewrite:
        proj.trim_binary()
    else:
        for addr in proj.target_addrs:
            l.info("Target 0x%08x: %s" % (addr, search_node_by_addr(proj.project, proj.cfg, addr)))
    

if __name__ == '__main__':
    main()

