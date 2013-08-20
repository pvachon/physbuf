tsl_dir=../tsl
obj=physbuf.o
target=physbuf_demo
cflags=-I../ -D_TSL_DEBUG -O0 -g -D_GNU_SOURCE -std=c99
ldflags=-L$(tsl_dir) -ltsl
CC=gcc

all: $(target)

.c.o:
	$(CC) -o $@ $(cflags) -c $<

$(target): $(obj)
	$(CC) -o $(target) $(obj) $(ldflags)

clean:
	$(RM) $(obj) $(target)

.PHONY: all clean
