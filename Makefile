# This Makefile is intended to be used in the R package byrongibby/grpcr
# Use CMakeLists.txt if you want to build this project in other contexts

CFILES=rexp.c rlist.c rserve.c utilities.c
OBJECTS=$(patsubst %.c, %.o, $(CFILES))

all: librserve-client.a

librserve-client.a: rexp.o rlist.o rserve.o utilities.o
	$(AR) rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) $(CPICFLAGS) -c -o $@ $^

clean:
	rm -rf librserve-client.a $(OBJECTS)
