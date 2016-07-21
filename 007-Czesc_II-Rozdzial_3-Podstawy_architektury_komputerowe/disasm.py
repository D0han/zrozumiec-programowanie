#!/usr/bin/python

import sys
import string
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


class disasm(object):
    def __init__(self, binary, vm_opcodes):
        self.binary = binary
        self.vm_opcodes = vm_opcodes
        self.code = defaultdict(lambda: [])
        self.pc = 0
        self.labels = {}
        self.instr = None

    def _handle_unknown_opcode(self):
        byte = self.binary[self.pc]
        if chr(byte) in set(string.printable) - set(string.whitespace):
            readable = chr(byte)
        else:
            readable = ''
        self.code[self.pc].append("db   \t0x%.2x\t; %s" % (byte, readable))
        self.pc += 1

    def _read_params(self):
        params = []
        params_bytes_readed = 0
        for arg_len in self.instr['params']:
            if not arg_len:
                continue
            params.append(self.binary[self.pc+arg_len+params_bytes_readed:
                                      self.pc+params_bytes_readed:-1])
            params_bytes_readed += arg_len
        # reverse arguments order for some instructions
        if self.instr['reverse']:
            params = params[::-1]
        return params

    def _write_mnemonic(self, params):
        instr_correct = True
        params_s = []
        for param in params:
            if not param:  # failed to read all params
                instr_correct = False
                self._handle_unknown_opcode()
                break
            params_s.append('0x%x' % int(''.join(['%.2x' % x for x in param]), 16))

        if instr_correct:
            self.code[self.pc].append("%s  \t%s" % (self.instr['name'].lower(), ', '.join(params_s)))
            self.pc += sum(self.instr['params'])+1

    def _handle_jump(self, params):
        self.code[self.pc].append(str(params))
        jump_to = int(''.join(['%.2x' % x for y in params for x in y]), 16) + \
                  1 + sum(self.instr['params'])
        if self.instr['name'] != 'VJMPR':  # this jump is not relative
            jump_to += self.pc
        if jump_to not in self.labels:
            self.labels[jump_to] = 'label%i' % len(self.labels)
        self.code[self.pc].append(str(jump_to))
        self.code[jump_to].insert(0, '%s:' % self.labels[jump_to])

    def analyze(self):
        while self.pc < len(self.binary):
            byte = self.binary[self.pc]
            if byte not in self.vm_opcodes:
                self._handle_unknown_opcode()
                continue
            self.instr = self.vm_opcodes[byte]
            params = self._read_params()
            # jumping?
            if self.instr['name'].startswith('VJ'):
                self._handle_jump(params)
            self._write_mnemonic(params)

    def print_out(self):
        print '%include "vm.inc"\n'
        for addr in sorted(self.code.keys()):
            for line in self.code[addr]:
                print "%.4x: %s" % (addr, line)
        print '>>> END'
        print self.labels


def main():
    if len(sys.argv) != 2:
        print "gimme binary to disasm!"
        sys.exit(1)
    with open(sys.argv[1], 'rb') as binary:
        data = [byte.encode('hex') for byte in binary.read()]
        data = [int(byte, 16) for byte in data]
        dis = disasm(data, VM_OPCODES)
        dis.analyze()
        dis.print_out()

if __name__ == '__main__':
    main()

