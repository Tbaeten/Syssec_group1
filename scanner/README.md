Working Code for the code scanner can be found in `scanner.c` under `/scanner`. 
Run `make` to get the scanner as a shared library. 
After compilation, run `LD_PRELOAD=$PWD/libscanner.so /bin/ls` to execute the scanner on the `/bin/ls` executable
