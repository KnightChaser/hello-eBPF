# Makefile

CC = gcc
CLANG = clang
CFLAGS = -O2 -g
PKG_CONFIG = pkg-config
LIBS = -lelf -lz

TARGET = tcp_status
BPF_OBJ = $(TARGET).bpf.o
USER_APP = $(TARGET)_user

LIBBPF_CFLAGS := $(shell $(PKG_CONFIG) --cflags libbpf)
LIBBPF_LDFLAGS := $(shell $(PKG_CONFIG) --libs libbpf)

all: $(BPF_OBJ) $(USER_APP)

$(BPF_OBJ): $(TARGET).bpf.c
	$(CLANG) $(CFLAGS) -target bpf -c $< -o $@

$(USER_APP): $(TARGET)_user.c
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) -o $@ $< $(LIBBPF_LDFLAGS) $(LIBS)

clean:
	rm -f $(BPF_OBJ)
	rm -f $(USER_APP)
