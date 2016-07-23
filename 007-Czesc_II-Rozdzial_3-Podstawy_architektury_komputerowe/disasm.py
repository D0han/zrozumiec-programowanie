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


class disasm(object):
    def __init__(self, binary, vm_opcodes):
        self.binary = binary
        self.vm_opcodes = vm_opcodes
        self.code = defaultdict(lambda: [])
        self.pc = 0
        self.labels = {}
        self.instr = None

    def _find_last_instr(self):
        last_pc = self.pc-1
        last_instr = False
        while last_pc >= 0:
            for instr in self.code[last_pc]:
                if 'instr' in instr:
                    last_pc = -1
                    last_instr = instr
                    break
            last_pc -= 1
        return last_instr

    def _handle_unknown_opcode(self):
        byte = self.binary[self.pc]
        last_instr = self._find_last_instr()
        if last_instr and last_instr['instr'] == 'db':
            last_instr['params'].append(byte)
            last_instr['comment'] += chr(byte)
        else:
            self.code[self.pc].append({'instr': "db",
                                       'params': [byte],
                                       'comment': chr(byte)})
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
            if not len(params[-1]):
                raise Exception
        # reverse arguments order for some instructions
        if self.instr['reverse']:
            params = params[::-1]
        return params

    def _write_mnemonic(self, params):
        params_s = []
        for param in params:
            try:
                params_s.append(int(''.join(['%.2x' % x for x in param]), 16))
            except:
                params_s.append(''.join(param))

        self.code[self.pc].append({'instr': self.instr['name'].lower(),
                                   'params': params_s,
                                   'comment': ''})
        self.pc += sum(self.instr['params'])+1

    def _handle_jump(self, params):
        jump_to = int(''.join(['%.2x' % x for y in params for x in y]), 16)
        if not self.instr['name'].endswith('R'):  # this is relative
            jump_to += self.pc + 1 + sum(self.instr['params'])
        jump_to %= 2**16
        if jump_to not in self.labels:
            self.labels[jump_to] = 'label%i' % len(self.labels)
            self.code[jump_to].insert(0, {'instr': '%s:' % self.labels[jump_to],
                                          'params': [],
                                          'comment': ''})
        params = [[self.labels[jump_to]]]
        return params

    def _probably_string(self):
        last_instr = self._find_last_instr()
        if last_instr and (last_instr['instr'] == 'db') \
                and (last_instr['params'][-1] != 0x0):
                    return True
        return False

    def analyze(self):
        while self.pc < len(self.binary):
            byte = self.binary[self.pc]
            if byte not in self.vm_opcodes:
                self._handle_unknown_opcode()
                continue
            self.instr = self.vm_opcodes[byte]
            try:
                params = self._read_params()
            except Exception:
                self._handle_unknown_opcode()
                continue
            # jumping or calling?
            if self.instr['name'].startswith('VJ') or self.instr['name'].startswith('VCALL'):
                if self._probably_string():
                    self._handle_unknown_opcode()
                    continue
                params = self._handle_jump(params)
            self._write_mnemonic(params)

    def print_out(self):
        print '%include "vm.inc"\n'
        for addr in sorted(self.code.keys()):
            if addr in self.labels:
                print ''
            for instr in self.code[addr]:
                line = ""
                #line = "%.4x: " % addr
                line += instr['instr']
                if ('params' in instr) and instr['params']:
                    params = []
                    for param in instr['params']:
                        try:
                            params.append('0x%.2x' % param)
                        except:
                            params.append(param)
                    line += '  \t%s' % ', '.join(params)
                if ('comment' in instr) and instr['comment']:
                    line += '\t; %s' % instr['comment'].__repr__()
                print line

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

