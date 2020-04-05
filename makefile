CC=gcc
CFLAGS=-Wall -Wextra
TRACER=sudo ./tracer
#TRACER=sudo valgrind --leak-check=full ./tracer
TRACEE=bin/tracee

# NOTE : if you want to compile with clang
# Compile only the tracer with clang with option -pie -fpie
# And compile the tracee with gcc otherwise it doesn't work

run:
	cd bin ; $(TRACER) tracee f1

ic:
	$(CC) $(CFLAGS) ./IndirectCall/tracer.c -o bin/tracer
	$(CC) $(CFLAGS) ./tracee/tracee.c -o bin/tracee
	$(TRACEE)

tr:
	$(CC) $(CFLAGS) ./Trampoline/tracer.c -o bin/tracer
	$(CC) $(CFLAGS) ./tracee/tracee.c -o bin/tracee
	$(TRACEE)

clean:
	rm -f bin/tracer
	rm -f bin/tracee
