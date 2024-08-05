#!/bin/bash
WD="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd ${WD}

echo -e "\nRemoving all previous encrypted files...\n"
rm -f *.tpmp
      
echo -e "\n#####################################################\n# Encrypting file.txt to file.txt.tpmp with the TPM #\n"#####################################################\"
cargo run

echo -e "\n####################################################\n# Decrypting file.txt.tpmp to std out with the TPM #\n"####################################################\"

cargo run -- --decrypt
