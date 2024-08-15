# extract-sig-list
Extract EFI signature lists (plain .esl or authenticated .auth) from files on Linux
## Introduction
This Linux tool extracts the content of an EFI signature list. The input file may be just an ESL, an ESL with four bytes header storing the EFI variable attributes (see below) or an authenticated EFI variable write aka **.auth** file.
You may use it to inspect PKs (platform keys), KEKs (key exchange keys), DBs (authorized signature databases), and DBXs (forbidden signature databases). This is especially useful if you want to see what is in the EFI variables dbDefault, dbxDefault, KEKDefault, and PKDefault that come with your machine (just one usecase).
## Prerequisites and building
You need a GNU Compiler Collection toolchain and the OpenSSL header files (plus libcrypto.so) on your system. Nothing else.
The OpenSSL libcrypto.so is required to parse X.509 certificates and PKCS#7 SignedData ASN.1 structures.
### Building
Just enter `make`. The Makefile is very simple (for GNU make), no GNU autotools required. You may customize the build by defining one or more of these make variables:
* **BUILD_DEBUG=1** to create a debug build with symbols (otherwise, a release build, stripped, is built - fully optimized)
* **BUILD_STATIC=1** to build a static binary (you can safely ignore the linker warnings, the tool does not use any dynamic library loading)
* **BIG_ENDIAN=1** if your target CPU architecture is Big Endian (default is: build for Little Endian machines)
* **OPENSSL_INC=<path>** if your OpenSSL headers are installed in a non-standard location
* **OPENSSL_LIB=<path>** where to find the libcrypto.so (also non-standard or homebrew OpenSSL)
### Build examples
```
make BUILD_STATIC=1 # create static binary
make BUILD_DEBUG=1 # create debug version
make BIG_ENDIAN=1 OPENSSL_INC=/home/anyone/my_openssl/inc OPENSSL_LIB=/home/anyone/my_openssl/lib # build with own OpenSSL build
```
### Makefile targets
There is a **clean** and an **install** target. Installation is performed in **/usr/local/bin**. Alternatively, just copy the ELF binary **extract-sig-list** manually.
## Running
Just enter `extract-sig-list` to display the help page.

The output is colored unless you specifiy **--no-colors** as the third (final) parameter. The first parameter is the input file, the second one is a folder name. All extracted EFI signatures are stored as separate files in this folder. If the folder does not exist, then it is created. **All output files are overwritten without warning.**

***Example:***
```
extract-sig-list pkDefault.esl pk-default-esl-files
```
Reads **pkDefault.esl**, displays some useful information about the entries, extracts and stores all entries in the folder **pk-default-esl-files**.
### Input file formats and efivarfs
The tool reads .esl as well as .auth files. .auth files contain authenticated EFI variable writes. The tool currently supports **EFI_VARIABLE_AUTHENTICATION_2** structures, see TODO below.

You do not need superuser rights as long as you are working with regular files. If you want to read directly from the efivarfs file system, then it has to be mounted first (as root). If you use **sudo** or if you are **root**, the tool automatically mounts the efivarfs as **/sys/firmware/efi/efivarfs**, performs the read operation, and unmounts it in its epilogue. The mount/unmount operations are performed only if the efivarfs was not already mounted before executing the tool.

You may define the environment variable **EFIVARFS_MOUNT_POINT** to an alternative mount point before executing the tool.

The tool inspects the first four bytes of an ESL file to check if it originates from the efivarfs. In this case, the first four bytes contain (always Little Endian) the EFI variable attributes, which are delivered this way from the efivarfs implementation in the Linux kernel.

### TODOs

Implement **EFI_VARIABLE_AUTHENTICATION_3** structure support.

### License

MIT







