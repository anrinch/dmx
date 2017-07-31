
all: mkmint

clean:
	-rm mkmint

mkmint: mkmint.c mkmint.h
	gcc -std=c99 -Wall mkmint.c -o mkmint -DDEBUG -lcrypto -luuid
