CC = gcc
AR = ar
FLAGS = -Wall -g

all: main

main: Main.o
	$(CC) -o main Main.o

main.o: Nain.c
	$(CC) $(FLAGS) -c Main.c 



clean:
	rm -f *.o *.so *.txt *.client *.server main 