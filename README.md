# CodeInjection

This is a master project about code injection using ptrace.
The goal of this project is to make a program that can modify a running application on the fly.
Hence the programm is able to inject some arbitrary code inside the running application and execute that code without leaving any trace.


## How it works :
- https://youtu.be/yuqg0Wx2KZ4

## To run the program
- make ic 
This command will compile the code for the indirect call version and run the tracee
- make tr
This command will compile the code for the trampoline version and run the tracee
