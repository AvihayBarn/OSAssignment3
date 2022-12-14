CC = gcc
AR = ar
FLAGS = -Wall -g

all: senderAndreciver

senderAndreciver: FileSenderAndReciver
	$(CC) -o FileSenderAndReciver.c FileSenderAndReciver
clean:
	rm -f *.o *.txt *.client *.server FileSenderAndReciver 