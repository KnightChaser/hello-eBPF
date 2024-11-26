# Compiler settings
CC = gcc
CLANG = clang
CFLAGS = -O2 -g
CLANG_FLAGS = -O2 -g -target bpf

# Paths
LIBBPF_PATH = /usr/include
LIBBPF_LIB = /usr/lib
BPF_HEADERS = -I$(LIBBPF_PATH) -I/usr/include/linux

# BPF Program
BPF_PROG = xdp_prog.o
BPF_SRC = xdp_prog.c

# Userspace Loader
LOADER = loader
LOADER_SRC = loader.c

# Libraries
LIBS = -lbpf

# Default target
all: $(BPF_PROG) $(LOADER)

# Compile the eBPF XDP program
$(BPF_PROG): $(BPF_SRC)
	@echo "Compiling eBPF program..."
	$(CLANG) $(CLANG_FLAGS) $(BPF_HEADERS) -c $< -o $@

# Compile the userspace loader
$(LOADER): $(LOADER_SRC)
	@echo "Compiling userspace loader..."
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

# Clean generated files
clean:
	@echo "Cleaning up..."
	rm -f $(BPF_PROG) $(LOADER)

.PHONY: all clean
