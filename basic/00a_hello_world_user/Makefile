BPFTOOL = bpftool
CLANG = clang
CC = gcc

TARGET := hello
BPF_OBJ := $(TARGET).bpf.o
USER_OBJ := $(TARGET)_user

.PHONY: all clean

all: $(BPF_OBJ) $(USER_OBJ)

$(BPF_OBJ): $(TARGET).bpf.c
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 -I. -c $< -o $@

$(USER_OBJ): $(TARGET)_user.c
	$(CC) -g -O2 -o $@ $< -lbpf -lelf

clean:
	rm -f $(BPF_OBJ) $(USER_OBJ)

