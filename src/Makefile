CC=gcc
u2spewfoo_CFLAGS=-g -O2 -DSF_VISIBILITY -fvisibility=hidden -Wall
#LIBS=-lnghttp2 -lz -ldaq_static -ldumbnet -lpcre -lpcap -lnsl -lm -lm  -lcrypto -ldl -L/usr/local/lib -ldaq_static_modules  -lsfbpf -lpcap -lsfbpf -lpcap -lz -llzma -lpthread -lpthread -lpthread

build: main

main: u2spewfoo.o main.o
	$(CC) $^ -o $@ $(LIBS)

main.o: main.c

u2spewfoo.o: u2spewfoo.c
	$(CC) -c $^ $(LIBS) $(u2spewfoo_CFLAGS)

clean:
	rm *.o main
