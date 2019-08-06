# AES-Encryption
AES in CBC mode to encrypt or decrypt files and text with a passphrase

## Purpose
to learn and implement encryption in java.
useful file encryption tool.

## Usage
- create executable jar with entry in the FileEncryption/Main class
  - java  -jar  someJarName.jar  -encrypt/decrypt  [filePath]  [passPhrase]
- use the classes and methods in some other exciting encryption venture

## Details
- contains CBCMode abstract class to extend to subclasses for implementing various
encryption or decryption methods
- two classes already extend CBCMode to implement encryption with a salt and passphrase

## TODO
- wipe key and passphrase after encrypt/decrypt from mem
- add secure file wipe method 
- directory encryption


