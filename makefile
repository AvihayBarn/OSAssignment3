CC = gcc
AR = ar
FLAGS = -Wall -g

all: sender&reciver

sender&reciver: FileSender&Reciver
	$(CC) -o FileSender&Reciver.c FileSender&Reciver
clean:
	rm -f *.o *.txt *.client *.server FileSender&Reciver 