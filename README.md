# Syssec_group1

## Part A : Trace system call
Working Code for the trace can be found in trace.cc under /trace. To execute, navigate to the folder and compile using 
``` make trace ```. After compilation, you can run the executable with: ```./trace <policy\_file\_path.txt> <bin>```

## Part B: Sandbox
Working code for the sandbox can be found in sandbox.c under /sandbox. Do not use the one in the parent folder as it a debug version for development use. The policy file for the hello_word program is provided. Use ```make all``` to generate executable of hello_world.c and shared library for the sandbox to be loaded into LD_Preload. Run ```LD\_PRELOAD=./sandbox.so ./hello\_world``` to execute the hello_world program with the sandbox, for further testing uncomment the mkdir function in hello_world.c and remake the executable.