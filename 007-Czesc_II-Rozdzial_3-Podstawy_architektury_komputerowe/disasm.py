#!/usr/bin/python

import sys
from collections import defaultdict


VM_OPCODES = {
    0x00: {'name': 'VMOV',  'params': (1, 1), 'reverse': False},
    0x01: {'name': 'VSET',  'params': (1, 4), 'reverse': False},
    0x02: {'name': 'VLD',   'params': (1, 1), 'reverse': False},
    0x03: {'name': 'VST',   'params': (1, 1), 'reverse': False},
    0x04: {'name': 'VLDB',  'params': (1, 1), 'reverse': False},
    0x05: {'name': 'VSTB',  'params': (1, 1), 'reverse': False},

    0x10: {'name': 'VADD',  'params': (1, 1), 'reverse': False},
    0x11: {'name': 'VSUB',  'params': (1, 1), 'reverse': False},
    0x12: {'name': 'VMUL',  'params': (1, 1), 'reverse': False},
    0x13: {'name': 'VDIV',  'params': (1, 1), 'reverse': False},
    0x14: {'name': 'VMOD',  'params': (1, 1), 'reverse': False},
    0x15: {'name': 'VOR',   'params': (1, 1), 'reverse': False},
    0x16: {'name': 'VAND',  'params': (1, 1), 'reverse': False},
    0x17: {'name': 'VXOR',  'params': (1, 1), 'reverse': False},
    0x18: {'name': 'VNOT',  'params': (1,),   'reverse': False},
    0x19: {'name': 'VSHL',  'params': (1, 1), 'reverse': False},
    0x1A: {'name': 'VSHR',  'params': (1, 1), 'reverse': False},

    0x20: {'name': 'VCMP',  'params': (1, 1), 'reverse': False},
    0x21: {'name': 'VJZ',   'params': (2,),   'reverse': False},
    0x22: {'name': 'VJNZ',  'params': (2,),   'reverse': False},
    0x23: {'name': 'VJC',   'params': (2,),   'reverse': False},
    0x24: {'name': 'VJNC',  'params': (2,),   'reverse': False},
    0x25: {'name': 'VJBE',  'params': (2,),   'reverse': False},
    0x26: {'name': 'VJA',   'params': (2,),   'reverse': False},

    0x30: {'name': 'VPUSH', 'params': (1,),   'reverse': False},
    0x31: {'name': 'VPOP',  'params': (1,),   'reverse': False},

    0x40: {'name': 'VJMP',  'params': (2,),   'reverse': False},
    0x41: {'name': 'VJMPR', 'params': (1,),   'reverse': False},
    0x42: {'name': 'VCALL', 'params': (2,),   'reverse': False},
    0x43: {'name': 'VCALLR','params': (1,),   'reverse': False},
    0x44: {'name': 'VRET',  'params': (0,),   'reverse': False},

    0xF0: {'name': 'VCRL',  'params': (1, 2), 'reverse': True},
    0xF1: {'name': 'VCRS',  'params': (1, 2), 'reverse': True},
    0xF2: {'name': 'VOUTB', 'params': (1, 1), 'reverse': True},
    0xF3: {'name': 'VINB',  'params': (1, 1), 'reverse': True},
    0xF4: {'name': 'VIRET', 'params': (0,),   'reverse': False},
    0xFE: {'name': 'VCRSH', 'params': (0,),   'reverse': False},
    0xFF: {'name': 'VOFF',  'params': (0,),   'reverse': False}
}


def disasm(binary):
    code = defaultdict(lambda: [])
    labels = {}
    pc = 0
#    print binary
    while pc < len(binary):
        byte = binary[pc]
        if byte not in VM_OPCODES:
            code[pc].append("db   \t0x%.2x\t; %s" % (byte, chr(byte)))
            pc += 1
            continue
        instr = VM_OPCODES[byte]
        params = []
        params_bytes_readed = 0
        for arg_len in instr['params']:
            if not arg_len:
                continue
            params.append(binary[pc+arg_len+params_bytes_readed:pc+params_bytes_readed:-1])
            params_bytes_readed += arg_len
        # reverse arguments order for some instructions
        if instr['reverse']:
            params = params[::-1]
        # skaczemy?
        if instr['name'].startswith('VJ'):
            code[pc].append(str(params))
            jump_to = int(''.join(['%.2x' % x for y in params for x in y]), 16) + \
                      pc + 1 + sum(instr['params'])
            if jump_to not in labels:
                labels[jump_to] = 'label%i' % len(labels)
            if instr['name'] != 'VJMPR':
                #tmp += pc
                pass
            code[pc].append(str(jump_to))
            code[jump_to].insert(0, '%s:' % labels[jump_to])

        code[pc].append("%s  " % instr['name'].lower())
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
            pc += sum(instr['params'])+1
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

