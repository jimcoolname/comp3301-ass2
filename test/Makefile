CC=gcc
CFLAGS=-Wall -std=gnu99
OBJS=echat.o

all: echat

clean:
	rm -f echat *.o

echat : $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o echat

echat.o : echat.c echat.h
	$(CC) $(CFLAGS) -c echat.c
