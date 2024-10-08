exploit: kutil.c exploit.c
	gcc kutil.c -o kutil.o -c
	gcc exploit.c -o exploit.o -c
	gcc -static -o exploit exploit.o kutil.o -luring -lpthread
