CC=gcc
CFLAGS=-g -O2 -DSF_VISIBILITY -fvisibility=hidden -Wall
#u2spewfoo_CFLAGS=-g -O2 -DSF_VISIBILITY -fvisibility=hidden -Wall
LIBS=-lmysqlclient

build: main

main: snortdb.o main.o
	$(CC) $^ -o $@ $(LIBS)

main.o: main.c

#u2spewfoo.o: u2spewfoo.c
#	$(CC) -c $^ $(u2spewfoo_CFLAGS)

snortdb.o: snortdb.c

clean:
	rm *.o main
