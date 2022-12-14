CC = gcc
AR = ar
FLAGS = -Wall -g

all: senderAndreciver

senderAndreciver: FileSenderAndReciver.o
	$(CC) -pthread -o FileSenderAndReciver FileSenderAndReciver.o
fileSenderAndReciver.o: FileSenderAndReciver.c
	$(CC) $(FLAGS) -c FileSenderAndReciver.c
clean:
	rm -f *.o *.txt *.client *.server FileSenderAndReciver 