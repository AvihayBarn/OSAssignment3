CC = gcc
AR = ar
FLAGS = -Wall -g

all: sender_and_reciver
run: sender_and_reciver
	./FileSenderAndReciver
sender_and_reciver: FileSenderAndReciver.o
	$(CC) -pthread -o FileSenderAndReciver FileSenderAndReciver.o

FileSenderAndReciver.o: FileSenderAndReciver.c
	$(CC) $(FLAGS) -c FileSenderAndReciver.c

clean:
	rm -f *.o *.so *.txt *.client *.server  FileSenderAndReciver 
