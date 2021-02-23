import logging
logging.getLogger('angr.analyses').setLevel(logging.INFO)

import os
import angr
from optparse import OptionParser

from .core import TrimAFL



def main():
    usage = "usage: %prog [options] <binary> <target func/addr>"
    parser = OptionParser(usage=usage)
    parser.add_option("-r", "--rewrite", dest="rewrite", action="store_true",
                      help="rewrite binary")

    (options, args) = parser.parse_args()
    if len(args) != 2 or not os.path.exists(args[0]):
        parser.error("Missing binary or target")
        exit(1)

    proj = TrimAFL(args[0], args[1])
    if options.rewrite:
        proj.trim_binary()
    

if __name__ == '__main__':
    main()

