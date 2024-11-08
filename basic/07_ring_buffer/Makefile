TARGET := exitsnoop

.PHONY: all clean

all: $(TARGET).bpf.o

$(TARGET).bpf.o: 
	../../ecc $(TARGET).bpf.c $(TARGET).h
	sudo ../../ecli run package.json

clean:
	rm $(TARGET).bpf.o
	rm package.json
	rm *.skel.json
