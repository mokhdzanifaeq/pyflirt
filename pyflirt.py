from core.signature import idasig
from core.binary import pe
from core.analyse import function
from core.generate import _map
from argparse import ArgumentParser
from sys import argv

def raw(path):
    fd = open(path, "rb")
    binary = fd.read()
    fd.close()
    return binary

if __name__ == '__main__':
    parser = ArgumentParser(description='generate map file for intel x86 binary based on flirt signature')
    parser.add_argument("-b", "--bin", metavar="path", help="path of binary file to be analysed", required=True)
    parser.add_argument("-s", "--sig", metavar="path", help="path of signature file to be analysed", required=True)
    parser.add_argument("-o", "--out", metavar="path", help="path of map file to be generated", required=True)
    if len(argv) == 1:
        parser.print_help()
        exit()
    args = parser.parse_args()
    try:
        raw_binary = raw(args.bin)
        raw_signature = raw(args.sig)
        pe_header = pe(raw_binary)
        flirt = idasig(raw_signature)
        anal = function(raw_binary, pe_header.sections, flirt.tree)
        _map(anal.functions, args.out)
    except Exception as e:
        print "[ERROR]", e