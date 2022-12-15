CC = gcc
AR = ar
FLAGS = -Wall -g

all: main
run: main
	./main
main: Main.o
	$(CC) -pthread -o main Main.o

main.o: Main.c
	$(CC) $(FLAGS) -c Main.c 

clean:
	rm -f *.o *.so *.client *.server rec_*.txt reciv*.txt file_100MB.txt main 
