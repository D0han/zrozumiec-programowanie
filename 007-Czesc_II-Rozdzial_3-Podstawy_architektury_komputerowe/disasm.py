#!/usr/bin/python

import sys
from collections import defaultdict
import vm_instr


def disasm(binary):
    code = defaultdict(lambda: [])
    labels = {}
    pc = 0
#    print vm_instr.VM_OPCODES
#    print binary
    while pc < len(binary):
        byte = binary[pc]
        if byte not in vm_instr.VM_OPCODES:
            code[pc].append("db   \t0x%.2x\t; %s" % (byte, chr(byte)))
            pc += 1
            continue
        instr = vm_instr.VM_OPCODES[byte]
        instr_name = instr[0].func_name
        params = []
        params_bytes_readed = 0
        for arg_len in instr[2]:
            if not arg_len:
                continue
            params.append(binary[pc+arg_len+params_bytes_readed:pc+params_bytes_readed:-1])
            params_bytes_readed += arg_len
        # reverse arguments order for some instructions
        if instr_name in ['VCRL', 'VCRS', 'VOUTB', 'VINB']:
            params = params[::-1]
        # skaczemy?
        if instr_name.startswith('VJ'):
            code[pc].append(str(params))
            jump_to = int(''.join(['%.2x' % x for y in params for x in y]), 16) + pc
            if jump_to not in labels:
                labels[jump_to] = 'label%i' % len(labels)
            if instr_name != 'VJMPR':
                #tmp += pc
                pass
            code[pc].append(str(jump_to))
            code[jump_to].insert(0, '%s:' % labels[jump_to])

        code[pc].append("%s  " % instr_name.lower())
        instr_correct = True
        if len(params):
            params_s = []
            for param in params:
                if not param: # failed to read all params
                    instr_correct = False
                    code[pc][-1] = "db   \t0x%.2x\t; %s" % (byte, chr(byte))
                    pc += 1
                    break
                params_s.append('0x%x' % int(''.join(['%.2x' % x for x in param]), 16))
            else:
                code[pc][-1] += "\t%s" % ', '.join(params_s)

        if instr_correct:
            pc += instr[1]+1
    print '%include "vm.inc"\n'
    for addr in sorted(code.keys()):
        for line in code[addr]:
            print "%.4x: %s" % (addr, line)
    print '>>> END'
    print labels

def main():
    if len(sys.argv) != 2:
        print "gimme binary to disasm!"
        sys.exit(1)
    with open(sys.argv[1], 'rb') as binary:
        data = [byte.encode('hex') for byte in binary.read()]
        data = [int(byte, 16) for byte in data]
        disasm(data)

if __name__ == '__main__':
    main()

