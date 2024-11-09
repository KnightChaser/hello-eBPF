# Makefile

CC = gcc
CLANG = clang
CFLAGS = -O2 -g
LIBS = -lbpf -lelf -lz

TARGET = execve
BPF_OBJ = $(TARGET).bpf.o
USER_APP = $(TARGET)_user

all: $(BPF_OBJ) $(USER_APP)

$(BPF_OBJ): $(TARGET).bpf.c
	$(CLANG) $(CFLAGS) -target bpf -c $< -o $@

$(USER_APP): $(TARGET)_user.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(BPF_OBJ) $(USER_APP)

