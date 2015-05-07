all: runpriv.cpp
	g++ -g -Wall -o myprog runpriv.cpp
clean:
	$(RM) myprog logfile.txt
