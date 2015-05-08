all: runpriv.c
	gcc -Wall -o myprog runpriv.c
clean:
	$(RM) myprog a.out 
