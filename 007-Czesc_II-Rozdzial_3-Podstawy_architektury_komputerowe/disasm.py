#!/usr/bin/python

import sys
import vm_instr


def disasm(binary):
    labels = {}
    pc = 0
#    print vm_instr.VM_OPCODES
#    print binary
    while pc < len(binary):
        byte = binary[pc]
        if byte not in vm_instr.VM_OPCODES:
            print "%.4x:      db   \t0x%.2x\t; %s" % (pc, byte, chr(byte))
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
        if instr_name.startswith('VJ'):
            tmp = int(''.join('%.2x' % x for x in params[0]), 16)
            if instr_name != 'VJMPR':
                #tmp += pc
                pass
            print tmp
            params[0][1] = tmp

        print "%.4x: 0x%.2x %s  " % (pc, byte, instr_name.lower()),
        if len(params):
            params_s = []
            for param in params:
                if not param:
                    continue
                params_s.append('0x%x' % int(''.join(['%.2x' % x for x in param]), 16))
            print "\t%s" % ', '.join(params_s)
        else:
            print ""

        # skaczemy?
        if instr_name.startswith('VJ'):
            print params
            jump_to = int(''.join(['%.2x' % x for y in params for x in y]), 16)
            if jump_to not in labels:
                labels[jump_to] = 'label%i' % len(labels)

        pc += instr[1]+1
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

