TARGET := runtime.bpf

.PHONY: all clean

all: $(TARGET).o

$(TARGET).o: 
	../../ecc $(TARGET).c
	sudo ../../ecli run package.json

clean:
	rm $(TARGET).o
	rm package.json
	rm *.skel.json
