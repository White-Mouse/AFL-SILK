# AFL-SILK
![](https://img.shields.io/hexpm/l/plug?style=flat-square)

  AFL-SILK is a component of SILK (A Hybrid Fuzzer) which is implemented based on AFL 2.57b. The main idea is that give easy paths more power.
  
  ## Environment
  - Tested on Ubuntu 16.04 64bit
  ## Install
  The installation process of AFL-SILK is simple because it is the same as that of AFL
 
    $ cd afl-silk
    $ make
    $ cd llvm-mode
    $ make
    $ cd ..
    $ sudo make install
  
  ## Usage
  AFL-SILK uses [gllvm](https://github.com/SRI-CSL/gllvm) or [wllvm](https://github.com/SRI-CSL/whole-program-llvm) to build target program. The following is an example of compiling with gllvm
  
    $ apt-get install flex bison
    $ git clone https://github.com/the-tcpdump-group/tcpdump.git
    $ git clone https://github.com/the-tcpdump-group/libpcap.git
    $ cd libpcap/ 
    $ CC=gclang  ./configure  --enable-shared=no
    $ make -j$(nproc)
    $ cd tcpdump
    $ CC=gclang  ./configure
    $ make -j$(nproc)
    $ get-bc tcpdump
    
    # Compile the bc with modified AFL-SILK/afl-clang-fast
    $ afl-clang-fast tcpdump.bc -o tcpdump
    
    # Prepare the initial seeds and start fuzzing
    $ afl-fuzz -i in/ -o out ./tcpdump -e -vv -nr @@
    

  ## LAVA-M
  AFL-SILK has better performance on LAVA-M than on AFL. The following is an example of fuzzing base64.
    
    $ cd /path-to-lava_corpus/LAVA-M/base64/coreutils-8.24-lava-safe
    $ sudo CC=/usr/local/go/bin/gclang CXX=/usr/local/go/bin/gclang++ ./configure FORCE_UNSAFE_CONFIGURE=1 --prefix=`pwd`/lava-install LIBS="-lacl"
    $ make
    $ make install
    $ cd lava-install/bin/
    $ get-bc base64
    $ mv base64.bc /path-to-lava_corpus/LAVA-M/base64
    $ /path-to-AFL-SILK/afl-clang-fast -i base64.bc base64_silk
    $ /path-to-AFL/afl-clang-fast -i base64.bc base64
    $ /path-to-AFL-SILK/afl-fuzz -i fuzzer_input -o out -M m ./base64_silk -d @@
    $ /path-to-AFL/afl-fuzz -i fuzzer_input -o out -S s ./base64 -d @@
    
