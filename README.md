DES/MDC-4
===================================

#### Features: ####
* DES encryption/decryption
* Digital signature with  the MDC-4 cryptographic hash function

#### Building: ####
    make

####Usage:####

    Usage: des [OPTION] [FILE]
    This tool encrypts/decrypts/signs a document using the DES encryption algorithm and the MDC-4 cryptographic hash function.

    Examples:
    	des -e archive.gz
    	des -d archive.gz.des

    Options:
    	-e	encrypt
    	-d	decrypt

#### Clean up: ####
    make clean