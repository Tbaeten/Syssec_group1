CC = gcc
CFLAGS = -Wall

HELLO_TARGET = hello_world
SANDBOX_TARGET = sandbox.so
HELLO_ASM_TARGET = hello_world.s

all: $(HELLO_TARGET) $(SANDBOX_TARGET) $(HELLO_ASM_TARGET)

$(HELLO_TARGET): hello_world.c
	$(CC) $(CFLAGS) $< -o $@
	chmod +x $@  # <--- THIS IS THE KEY FIX

$(SANDBOX_TARGET): sandbox.c
	$(CC) -shared -fPIC $(CFLAGS) $< -o $@

$(HELLO_ASM_TARGET): hello_world.c
	$(CC) -S $(CFLAGS) $< -o $@

clean:
	rm -f $(HELLO_TARGET) $(SANDBOX_TARGET) $(HELLO_ASM_TARGET) *.o

.PHONY: all clean