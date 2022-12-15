#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <unistd.h>




#define ERROR -1
#define LINESIZE 1024
#define PORT 8080
#define SOCK_PATH "tpf_unix_sock.server"
#define SERVER_PATH "tpf_unix_sock.server"
#define CLIENT_PATH "tpf_unix_sock.client"

//size of 100 megabytes
const int BUFFER_SIZE = 104857600;


pthread_mutex_t mutex;


char* LOCAL_IP = "127.0.0.1";
clock_t start;
clock_t end;
char* fileName = "file_100MB.txt";






//Every method has function to send and recive the data and a wraping function

int TCPsend();
int TCPrecive();
int TCP();

int UDPsend();
int UDPrecive();
int UDP();

int UDS_stream_send();
int UDS_stream_recive();
int UDS_stream();


int UDS_datagram_send();
int UDS_datagram_recive();
int UDS_datagram();

void* SharedMemoryFirstThread(void* arg);
void* SharedMemorySecondThread();
void threads_shared_mem();

int checkSum(char* input_filename);
int MMAP();
int PIPE();






int main(int argc, char* argv[])
{

    const char* methods[] = { "TCP_IPv4","UDP_IPv6","UDS_diagram","UDS_stream","MMap","Pipe","Shared Memory"};
    
    
    char *buffer = (char *)malloc(BUFFER_SIZE * sizeof(char));
    if (!buffer)
    {
        perror("malloc");
        return 1;
    }

    
    for (int i = 0; i < BUFFER_SIZE; i++)
    {
        buffer[i] = rand() % 256;
    }

    
    FILE *file = fopen(fileName, "wb");
    if (!file)
    {
        perror("fopen");
        return 1;
    }

    
    size_t bytes_written = fwrite(buffer, sizeof(char), BUFFER_SIZE, file);
    if (bytes_written != BUFFER_SIZE)
    {
        fprintf(stderr, "Error writing to file\n");
        return 1;
    }

    
    if (fclose(file) != 0)
    {
        perror("fclose");
        return 1;
    }

    
    free(buffer);

    for (int i = 0; i < 7; i++)
    {
        char* method = methods[i];
         if(strcmp("TCP_IPv4", method) == 0)
         {
             TCP();
         }
         else if(strcmp("UDP_IPv6", method) == 0)
         {
             UDP();
         }
         else if(strcmp("UDS_diagram", method) == 0)
         {
             UDS_datagram();
         }
         else if(strcmp("UDS_stream", method) == 0)
         {
             UDS_stream();
         }
         else if(strcmp("MMap", method) == 0)
         {
             MMAP();
         }
         else if(strcmp("Pipe", method) == 0)
         {
             PIPE();
         }
         else if(strcmp("Shared Memory", method) == 0)
         {
             threads_shared_mem();
         }
         
    }
    
    
    
   
    
    
    
    
    return 0;
}
















int checkSum(char *input_filename)
{
    int file2 = open(input_filename, O_CREAT | O_RDWR);
    int file1 = open(fileName, O_CREAT | O_RDWR);
  
    if (file1 == -1)
    {
        perror("open files");
    }
    size_t r;
    long long tmp_sum1;
    char buff[LINESIZE];
    int sum1 = 0;
    while ((r = read(file1, buff, sizeof(buff))) > 0)
    {
        tmp_sum1 = 0;
        for (int i = 0; i < r; i++)
            tmp_sum1 += buff[i];
        bzero(buff, LINESIZE);
        sum1 += tmp_sum1;
    }

    if (file2 == -1)
    {
        perror("open");
    }

    size_t r2;
    char buffile2[LINESIZE];

    int sum2 = 0;
    int tmp_sum2;
    while ((r2 = read(file2, buffile2, sizeof(buffile2))) > 0)
    {
        tmp_sum2 = 0;
        for (int i = 0; i < r2; i++)
            tmp_sum2 += buffile2[i];
        bzero(buffile2, LINESIZE);
        sum2 += tmp_sum2;
    }
    close(file1);
    close(file2);

    if (sum2 == sum1)
    {
        return 1;
    }
    else
    {
        return -1;
    }
}

/
int TCPsend()
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = inet_addr(LOCAL_IP);

    
    int con = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    if (con == -1)
    {
        perror("connect");
        close(sockfd);
        exit(1);
    }
    
    FILE *fp = fopen(fileName, "rb");
    if (!fp)
    {
        perror("fopen sender");
        return -1;
    }

    
    char buffer[LINESIZE];
    size_t bytes_read;
    start = clock();
    printf("TCP/IPv4 Socket - start: %f\n", (float)start / CLOCKS_PER_SEC);
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), fp)) > 0)
    {
        send(sockfd, buffer, bytes_read, 0);
        bzero(buffer, LINESIZE);
    }
    
    fclose(fp);
    close(sockfd);
    return 0;
}

int TCPrecive()
{
   
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);

    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    {
        perror("bind");
        return -1;
    }

    
    if (listen(sock_fd, 10) == -1)
    {
        perror("listen");
        return -1;
    }

    
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    int client_fd = accept(sock_fd, (struct sockaddr *)&client_addr, &client_addr_len);
    if (client_fd == -1)
    {
        perror("accept");
        return -1;
    }

    FILE *file = fopen("rec_file_tcp.txt", "wb");
    if (file == NULL)
    {
        perror("reciver file");
        return -1;
    }
    
    char buf[LINESIZE];
    size_t num_bytes_received;
    size_t num_bytes_written;
    while ((num_bytes_received = recv(client_fd, buf, sizeof(buf), 0)) > 0)
    {
        num_bytes_written = fwrite(buf, sizeof(char), num_bytes_received, file);
        bzero(buf, LINESIZE);
    }

    if (num_bytes_received == -1)
    {
        perror("recive");
        return -1;
    }
    close(sock_fd);
    
    fclose(file);

    end = clock();
    int c = checkSum("rec_file_tcp.txt");
    if (c == 1)
    {
        printf("TCP/IPv4 Socket - end: %f\n", (double)end / CLOCKS_PER_SEC);
    }
    else if (c == -1)
    {
        printf("TCP/IPv4 Socket - end: -1\n");
    }
    return 0;
}

int TCP()
{
    int pid = fork();
    if (pid < 0)
    
    {
        return -1;
    }
    if (pid == 0)
    {
        TCPsend();
        exit(0);
    }
    else
    {
        TCPrecive();
        wait(NULL);
    }
}


int UDPrecive()
{
    int sockfd;
    char buffer[LINESIZE];
    struct sockaddr_in servaddr, cliaddr;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));
    memset(buffer, 0, LINESIZE);
    
    servaddr.sin_family = AF_INET; 
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(12345);

    
    if (bind(sockfd, (const struct sockaddr *)&servaddr,
             sizeof(servaddr)) < 0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    FILE *file = fopen("rec_file_udp.txt", "wb");
    if (file == NULL)
    {
        perror("reciver file");
        return -1;
    }

    int len = sizeof(cliaddr);
    size_t num_bytes_received;
    size_t num_bytes_written;
    while ((num_bytes_received = recvfrom(sockfd, (char *)buffer, LINESIZE,
                                          MSG_WAITALL, (struct sockaddr *)&cliaddr,
                                          &len)) > 0)
    {
        if (num_bytes_received == -1)
        {
            perror("recive");
            return -1;
        }
        
        num_bytes_written = fwrite(buffer, sizeof(char), num_bytes_received, file);
       
        bzero(buffer, LINESIZE);
    }

    fclose(file);
    end = clock();
    int c = checkSum("rec_file_udp.txt");
    if (c == 1)
    {
        printf("UDP/IPv6 Socket - end: %f\n", (double)end / CLOCKS_PER_SEC);
    }
    else if (c == -1)
    {
        printf("UDP/IPv6 Socket - end: -1\n");
    }
    close(sockfd);
    return 0;
}

int UDPsend()
{
    int sockfd;
    char buffer[LINESIZE];
    struct sockaddr_in servaddr;

    
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    memset(buffer, 0, LINESIZE);
  
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(12345);
    servaddr.sin_addr.s_addr = INADDR_ANY;

    
    FILE *fp = fopen(fileName, "rb");
    if (!fp)
    {
        perror("fopen sender");
        return -1;
    }

  
    size_t bytes_read;
    start = clock();
    printf("UDP/IPv6 Socket - start: %f\n", (double)start / CLOCKS_PER_SEC);

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), fp)) > 0)
    {
        size_t bytes_sent = 0;
        while (bytes_sent != bytes_read)
        {
            size_t ret = sendto(sockfd, (const char *)buffer, bytes_read, MSG_CONFIRM, (const struct sockaddr *)&servaddr, sizeof(servaddr));
            if (ret > 0)
            {
                bytes_sent += ret;
            }
            else if (ret < 0)
            {
                perror("send");
                exit(1);
            }
        }
        bzero(buffer, LINESIZE);
    }
    sendto(sockfd, "", 0, 0, (const struct sockaddr *)&servaddr, sizeof(servaddr));
    
    fclose(fp);
    close(sockfd);
    return 0;
}

int UDP()
{
    int pid = fork();
    if (pid < 0)
    {
        return -1;
    }
    if (pid == 0)
    {
        UDPsend();
        exit(0);
    }
    else
    {
        UDPrecive();
        wait(NULL);
    }
}


int UDS_stream_recive()
{
    int server_sock, client_sock, len, rc;
    int bytes_rec = 0;
    struct sockaddr_un server_sockaddr;
    struct sockaddr_un client_sockaddr;
    char buf[LINESIZE];
    int backlog = 10;
    memset(&server_sockaddr, 0, sizeof(struct sockaddr_un));
    memset(&client_sockaddr, 0, sizeof(struct sockaddr_un));
    memset(buf, 0, LINESIZE);

  
    server_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_sock == -1)
    {
        printf("SOCKET ERROR");
        exit(1);
    }

    
    server_sockaddr.sun_family = AF_UNIX;
    strcpy(server_sockaddr.sun_path, input_filename);
    len = sizeof(server_sockaddr);

    unlink(input_filename);
    rc = bind(server_sock, (struct sockaddr *)&server_sockaddr, len);
    if (rc == -1)
    {
        printf("BIND ERROR");
        close(server_sock);
        exit(1);
    }

    rc = listen(server_sock, backlog);
    if (rc == -1)
    {
        printf("LISTEN ERROR");
        close(server_sock);
        exit(1);
    }
 
    client_sock = accept(server_sock, (struct sockaddr *)&client_sockaddr, &len);
    if (client_sock == -1)
    {
        printf("ACCEPT ERROR");
        close(server_sock);
        close(client_sock);
        exit(1);
    }


    len = sizeof(client_sockaddr);
    rc = getpeername(client_sock, (struct sockaddr *)&client_sockaddr, &len);
    if (rc == -1)
    {
        printf("GETPEERNAME ERROR");
        close(server_sock);
        close(client_sock);
        exit(1);
    }
    else
    {
    }



    FILE *file = fopen("rec_file_uds.txt", "wb");
    if (file == NULL)
    {
        perror("reciver file");
        return -1;
    }

    size_t num_bytes_received;
    size_t num_bytes_written;
    while ((num_bytes_received = recv(client_sock, buf, sizeof(buf), 0)) > 0)
    {
        num_bytes_written = fwrite(buf, sizeof(char), num_bytes_received, file);
        bzero(buf, LINESIZE);
    }

    if (num_bytes_received == -1)
    {
        perror("recive");
        return -1;
    }
    fclose(file);

    end = clock();
    int c = checkSum("rec_file_uds.txt");
    if (c == 1)
    {
        printf("UDS - Stream socket - end: %f\n", (double)end / CLOCKS_PER_SEC);
    }
    else if (c == -1)
    {
        printf("UDS - Stream socket - end: -1\n");
    }
    close(server_sock);
    close(client_sock);
    return 0;
}

int UDS_stream_send()
{
    int client_sock, rc, len;
    struct sockaddr_un server_sockaddr;
    struct sockaddr_un client_sockaddr;
    char buf[LINESIZE];
    memset(&server_sockaddr, 0, sizeof(struct sockaddr_un));
    memset(&client_sockaddr, 0, sizeof(struct sockaddr_un));
    memset(buf, 0, LINESIZE);

    client_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (client_sock == -1)
    {
        printf("SOCKET ERROR");
        exit(1);
    }


    client_sockaddr.sun_family = AF_UNIX;
    strcpy(client_sockaddr.sun_path, CLIENT_PATH);
    len = sizeof(client_sockaddr);

    unlink(CLIENT_PATH);
    rc = bind(client_sock, (struct sockaddr *)&client_sockaddr, len);
    if (rc == -1)
    {
        printf("BIND ERROR");
        close(client_sock);
        exit(1);
    }

    server_sockaddr.sun_family = AF_UNIX;
    strcpy(server_sockaddr.sun_path, SERVER_PATH);
    rc = connect(client_sock, (struct sockaddr *)&server_sockaddr, len);
    if (rc == -1)
    {
        printf("CONNECT ERROR");
        close(client_sock);
        exit(1);
    }

    FILE *fp = fopen(fileName, "rb");
    if (!fp)
    {
        perror("fopen sender");
        return -1;
    }

    size_t bytes_read;
    start = clock();
    printf("UDS - Stream socket - start: %f\n", (double)start / CLOCKS_PER_SEC);
    while ((bytes_read = fread(buf, 1, sizeof(buf), fp)) > 0)
    {
        send(client_sock, buf, bytes_read, 0);
        bzero(buf, LINESIZE);
    }

    fclose(fp);
    close(client_sock);

    return 0;
}

int UDS_stream()
{
    int pid = fork();
    if (pid < 0)
    {
        return -1;
    }
    if (pid == 0)
    {
        UDS_stream_send();
        exit(0);
    }
    else
    {
        UDS_stream_recive();
        wait(NULL);
    }
}

int UDS_datagram_recive()
{
    int server_sock, len, rc;
    struct sockaddr_un server_sockaddr, peer_sock;
    char buf[LINESIZE];
    memset(&server_sockaddr, 0, sizeof(struct sockaddr_un));
    memset(buf, 0, LINESIZE);


    server_sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (server_sock == -1)
    {
        printf("SOCKET ERROR");
        exit(1);
    }
    else
    {
    }


    server_sockaddr.sun_family = AF_UNIX;
    strcpy(server_sockaddr.sun_path, input_filename);
    len = sizeof(server_sockaddr);
    unlink(input_filename);
    rc = bind(server_sock, (struct sockaddr *)&server_sockaddr, len);
    if (rc == -1)
    {
        printf("BIND ERROR");
        close(server_sock);
        exit(1);
    }

    FILE *file = fopen("rec_file_uds_dg.txt", "wb");
    if (file == NULL)
    {
        perror("reciver file");
        return -1;
    }

    size_t bytes_rec = 0;

    while ((bytes_rec = recvfrom(server_sock, (char *)buf, sizeof(buf), MSG_WAITALL, (struct sockaddr *)&server_sockaddr, &len)) > 0)
    {
        if (bytes_rec == -1)
        {
            printf("RECVFROM ERROR");
            close(server_sock);
            exit(1);
        }
        else
        {
            fwrite(buf, sizeof(char), bytes_rec, file);
            bzero(buf, LINESIZE);
        }
    }
    fclose(file);
    end = clock();
    int c = checkSum("rec_file_uds_dg.txt");
    if (c == 1)
    {
        printf("UDS - Dgram socket - end: %f\n", (double)end / CLOCKS_PER_SEC);
    }
    else if (c == -1)
    {
        printf("UDS - Dgram socket - end: -1\n");
    }

    close(server_sock);

    return 0;
}

int UDS_datagram_send()
{
    int client_sock, rc;
    struct sockaddr_un remote;
    char buf[LINESIZE];
    memset(&remote, 0, sizeof(struct sockaddr_un));
    memset(buf, 0, LINESIZE);
 
    client_sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (client_sock == -1)
    {
        printf("SOCKET ERROR");
        exit(1);
    }


    remote.sun_family = AF_UNIX;
    strcpy(remote.sun_path, SERVER_PATH);




    FILE *fp = fopen(fileName, "rb");
    if (!fp)
    {
        perror("fopen sender");
        return -1;
    }

    size_t bytes_read;
    start = clock();
    printf("UDS - Dgram socket - start: %f\n", (double)start / CLOCKS_PER_SEC);
    while ((bytes_read = fread(buf, 1, sizeof(buf), fp)) > 0)
    {
        sendto(client_sock, (const char *)buf, bytes_read, MSG_CONFIRM, (const struct sockaddr *)&remote, sizeof(remote));
        if (rc == -1)
        {
            printf("SENDTO ERROR\n");
            close(client_sock);
            exit(1);
        }
        else
        {
            bzero(buf, LINESIZE);
        }
    }
    sendto(client_sock, "", 0, 0, (struct sockaddr *)&remote, sizeof(remote));

   
    fclose(fp);
    close(client_sock);

    return 0;
}

int UDS_datagram()
{

    int pid = fork();
    if (pid < 0)
    {
        return -1;
    }
    if (pid == 0)
    {
        UDS_datagram_send();
        exit(0);
    }
    else
    {
        UDS_datagram_recive();
        wait(NULL);
    }
}

int MMAP()
{

    int fd = open(fileName, O_RDWR);
    if (fd == -1)
    {
        perror("open");
        exit(1);
    }
    
    struct stat st;
    fstat(fd, &st);
    size_t filesize = st.st_size;

    
    start = clock();
    printf("MMAP - start: %f\n", (double)start / CLOCKS_PER_SEC);
    void *addr = mmap(NULL, filesize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED)
    {
        perror("mmap");
        exit(1);
    }

    FILE *file = fopen("rec_file_mmap.txt", "wb");
    if (file == NULL)
    {
        perror("reciver file");
        return -1;
    }
    for (size_t i = 0; i < filesize; i++)
    {
        fwrite(&(*((char *)addr)), 1, sizeof(char), file);
        addr++;
    }

    fclose(file);
    end = clock();
    int c = checkSum("rec_file_mmap.txt");
    if (c == 1)
    {
        printf("MMAP - end: %f\n", (double)end / CLOCKS_PER_SEC);
    }
    else if (c == -1)
    {
        printf("MMAP - end: -1\n");
    }

    return 0;
}

int PIPE()
{
    int filedes[2];
    pid_t childpid;

    pipe(filedes);

    if ((childpid = fork()) == -1)
    {
        perror("fork");
        exit(1);
    }

    if (childpid == 0)
    {
        close(filedes[0]);

        char buf[LINESIZE];
        FILE *fp = fopen(fileName, "rb");
        if (!fp)
        {
            perror("fopen sender");
            return -1;
        }

        size_t bytes_read;
        start = clock();
        printf("PIPE - start: %f\n", (double)start / CLOCKS_PER_SEC);
        while ((bytes_read = fread(buf, 1, sizeof(buf), fp)) > 0)
        {
            write(filedes[1], buf, bytes_read);
        }
        close(filedes[1]);
        exit(0);
    }
    else
    {
        
        close(filedes[1]); 

        FILE *file = fopen("rec_file_pipe.txt", "wb");
        if (file == NULL)
        {
            perror("reciver file");
            return -1;
        }
        char readbuffer[LINESIZE];
        size_t num_bytes_received;
        
        while (num_bytes_received = read(filedes[0], readbuffer, sizeof(readbuffer)))
        {

            fwrite(readbuffer, sizeof(char), num_bytes_received, file);
            bzero(readbuffer, LINESIZE);
        }
        close(filedes[0]);
        fclose(file);

        end = clock();
        int c = checkSum("rec_file_pipe.txt");
        if (c == 1)
        {
            printf("PIPE - end: %f\n", (double)end / CLOCKS_PER_SEC);
        }
        else if (c == -1)
        {
            printf("PIPE - end: -1\n");
        }
    }

    return 0;
}

void *SharedMemoryFirstThread(void *arg)
{
 
    void *addr = (void *)arg;
 
    struct stat file_stat;
    if (stat(fileName, &file_stat) != 0)
    {
        perror("Error getting file information");
        exit(1);
    }

    
    int dest_fd = open("rec_file_shared.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dest_fd == -1)
    {
        perror("OPEN");
        exit(1);
    }

   
    size_t num_bytes = 0;
    ssize_t bytes_written = 0;
    while (num_bytes < file_stat.st_size && bytes_written != -1)
    {
        bytes_written = write(dest_fd, addr, file_stat.st_size - num_bytes);
        if (bytes_written == -1)
        {
            perror("WRITE");
            exit(1);
        }
        num_bytes += bytes_written;
    }
    close(dest_fd);


    return NULL;
}

void *SharedMemorySecondThread()
{
    start = clock();
    printf("SHARED MEMORY - start: %f\n", (double)start / CLOCKS_PER_SEC);

    int fd = open(fileName, O_RDONLY);

    size_t file_size = lseek(fd, 0, SEEK_END);

    void *addr = mmap(NULL, file_size, PROT_READ, MAP_SHARED, fd, 0);

    pthread_t thread;
    pthread_create(&thread, NULL, SharedMemoryFirstThread, addr);
    
    pthread_join(thread, NULL);

    munmap(addr, file_size);
    close(fd);
    end = clock();
    int c = checkSum("rec_file_shared.txt");
    if (c == 1)
    {
        printf("SHARED MEMORY - end: %f\n", (double)end / CLOCKS_PER_SEC);
    }
    else if (c == -1)
    {
        printf("SHARED MEMORY - end: -1\n");
    }


   
    return NULL;
}

void threads_shared_mem()
{
    pthread_t thread;
    pthread_create(&thread, NULL, SharedMemorySecondThread, fileName);

   
    pthread_join(thread, NULL);
}

