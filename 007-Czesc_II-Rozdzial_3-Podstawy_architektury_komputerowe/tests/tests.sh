#!/bin/bash

mkdir -p disasm_test
cd disasm_test
ln -fs ../../vm.inc .

outcome=0

for src in ../../*.nasm; do
    test_name=$(basename "${src}" .nasm)
    echo "Testing $test_name"
    nasm -o "${test_name}" "../../${test_name}.nasm"
    ../../disasm.py "${test_name}" > "${test_name}_disasm.nasm"
    nasm "${test_name}_disasm.nasm"
    hexdump -C "${test_name}" > "${test_name}.hex"
    hexdump -C "${test_name}_disasm" > "${test_name}_disasm.hex"
    diff "${test_name}.hex" "${test_name}_disasm.hex"
    let outcome+=$?
    echo ""
done

exit $outcome
