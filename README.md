# Simple Deqryptor for QUA packed qRat [19M07A]

Copyright (c) 2019, tan2pow16. All rights reserved.

**Please beware the `malware` folder contains LIVE MALWARE. Handle the files with extra caution.**

## Background
This is a simple unpacker I made for fun to decrypt a recent qua sample uploaded to HybridAnalysis on Jul., 1st:
 * https://www.hybrid-analysis.com/sample/431a970604e165595132da85d27a0c830a9a4a1e7d48d813fba63e2c7c9bcb46?environmentId=100
 
As of Jul., 7, 2019, the raw sample remains almost FUD, and the unpacked stub remains FULLY FUD.
 * Original sample: https://www.virustotal.com/gui/file/431a970604e165595132da85d27a0c830a9a4a1e7d48d813fba63e2c7c9bcb46/detection
 * Decrypted stub: https://www.virustotal.com/gui/file/a5727ddafb41d5a0417a87eddfd13f65d74c974872dfd3827fe1c64abff24f23/detection

## Tools
Tools I used to analyze the sample:
 * Bytecode Viewer by Konloch: https://github.com/konloch/bytecode-viewer
 * CFR decompiler (integrated in the toolset above): https://github.com/leibnitz27/cfr
 
## Usage
Usage: `java -jar ./bin/Deqryptor.jar [mode] <input_path> [mode_args ...] <output_dir>`
 * `mode`: An integer stating the decryption step. `1` for decrypting the class `q0b4/bootstrap/templates/Header.class`; and `2` for decrypting the entry mapping and the stub.
 * `input_path`: The malware sample file path.
 * `mode_args ... `:
   * For `mode == 1`: `<key_AES_hex> <encrypted_entry_path>`
     * `key_AES_hex`: The HEX representation of the AES key.
     * `encrypted_entry_path`: The path of the encrypted class in the sample JAR.
   * For `mode == 2`: `[count] <encrypted_paths ... > [decrypted_item_size] [encrypted_item_size] <key1> <key2>`
     * `count`: The number of encrypted_paths for the mapping file item.
     * `encrypted_paths ... `: Encrypted entry paths storing the encrypted mapping file segments. Must contain `count` strings.
     * `decrypted_item_size`: Decrypted size of the mapping serialized object file. (Currently unused in the code. Assign whatever number you want)
     * `encrypted_item_size`: Encrypted size of the mapping serialized object file.
     * `key1`: The first part of the encryption key.
     * `key2`: The second part of the encryption key.
 
## Instructions
**Please perform the statements below in VIRTUALIZED ENVIRONMENT as some malware components WILL BE LOADED INTO THE MEMORY. I don't guarantee the process is 100% safe!**

 * Decompile the sample with CFR decompiler. Since the 1st layer of the packer are usually "innocuous looking" to decieve anti-malware products, the classes are usually simple and easy-to-decompile. I used Bytecode Viewer to do the job for me with ease.
 * Use an IDE to edit the codes. One may find a method-call `ClassLoader.getResourceAsStream(String)`. Extract the `String` parameter as the `Header` class entry path. I used dynamical analysis and just print out the string.
 * Extract the AES key used to decrypt the resource. This may also simply be done by modifying the decompiled codes above. Just catch an exception and spit out a zero-sized byte array.
 * Use the path and key to decrypt the `Header` class file. You may find `step1.bat` useful.
 * Decompile the decrypt class. You may now find the parameters required for `step2.bat`. If the requirements are met, it will spit out the mapping.ser and the stub containing the decrypted classes.
