LDLIBS=-lpcap

all: packet-stat

packet-stat: main.o class.o struct.o ip.o
		$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ -g
	
clean:
	rm -rf packet-stat *.o