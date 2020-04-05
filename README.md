# Code Injection using ptrace

This is a master project about code injection using ptrace.
The goal of this project is to make a program that can modify a running application on the fly.
Hence the programm is able to inject some arbitrary code inside the running application and execute that code without leaving any trace.
> Two version of the injection is available, one done by the way of an indirect call and an other by creating a trampoline.
> In the indirect call version we execute the injected code once and we don't leave any trace.
> In the trampoline one we don't clear anything as we want the injected code to be executed everytime the function specify is called by the tracee.

## How it works :
- https://youtu.be/yuqg0Wx2KZ4


## To run the program
- make ic **or** make tr
- make run 

Or if you want to run it with you own tracee

- run the tracee
- sudo tracer [process name] [function name]

> *The processus secify need to be run before the execution of the tracer.*
> *The function specify need to be an existing function in the tracee.*

# 
> *Note that the injected function take as parameter an integer and return an integer.
> If you wish to change its purpose you can modify the call_func() function inside tracer.c and change the type of the parameter name 'parameter' and also the return type of the function.*
