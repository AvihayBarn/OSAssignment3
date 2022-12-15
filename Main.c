#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/wait.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <pthread.h>

// define for UDS
#define SOCK_PATH "tpf_unix_sock.server"
#define SERVER_PATH "tpf_unix_sock.server"
#define CLIENT_PATH "tpf_unix_sock.client"
#define ERROR -1
#define MAX 1024
#define PORT 8080
const int BUFFER_SIZE = 104857600 ;// 100 MB

char globalBuf[MAX]; // shared mem
pthread_mutex_t mutex;
int flag = -1;
#define mb100 104857600 //Allocate 100 MB memory block 
char *IP = "127.0.0.1";
clock_t start;
clock_t end;
char *fileName = "file_100MB.txt";

int* GenerateMemoryBlock()
{
    time_t t;
    // intializes random number generator
    srand((unsigned) time(&t));

   int* pBytes = malloc(sizeof(int) * mb100);
   if (!pBytes){
     perror("malloc failed\n");
   }

    // Write 100 MB data 1000 times.
   for( int Index = 0; Index < mb100; ++Index )
   {
      pBytes[ Index ] = (int) rand();
   }

   return pBytes;
}

void create100MBBinaryFile()
{
    FILE *fp = fopen(fileName, "wb");
    clock_t start_time, end_time;

    start_time = clock();

    // open file.

    if(fp == NULL) {
        perror("fopen faild!\n");
        
    }

   // Get data.
   int* pData = GenerateMemoryBlock();

   // write to file 
    size_t write_file =fwrite(pData , sizeof(int) ,mb100 , fp);
    if (write_file != mb100)
    {
        perror("fwrite faild!\n");
        
    }
    free(pData);

    end_time = clock();
    // get the time takenin seconds
}

int checkSum(char *file_name2)
{
    int f2 = open(file_name2, O_CREAT | O_RDWR);
    int f1 = open(fileName, O_CREAT | O_RDWR);
    // if we had problem to open the files.
    if (f1 == -1)
    {
        perror("open files");
    }
    size_t r;
    long long tmp_sum1;
    char buff[MAX];
    int sum1 = 0;
    while ((r = read(f1, buff, sizeof(buff))) > 0)
    {
        tmp_sum1 = 0;
        for (int i = 0; i < r; i++)
            tmp_sum1 += buff[i];
        bzero(buff, MAX);
        sum1 += tmp_sum1;
    }

    // if we had problem to open the files.
    if (f2 == -1)
    {
        perror("open");
    }

    size_t r2;
    char buff2[MAX];

    int sum2 = 0;
    int tmp_sum2;
    while ((r2 = read(f2, buff2, sizeof(buff2))) > 0)
    {
        tmp_sum2 = 0;
        for (int i = 0; i < r2; i++)
            tmp_sum2 += buff2[i];
        bzero(buff2, MAX);
        sum2 += tmp_sum2;
    }
    close(f1);
    close(f2);

    if (sum2 == sum1)
    {
        return 1;
    }
    else
    {
        return -1;
    }
}

/* TCP */
int senderTCP()
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    // Set the address and port of the remote host.
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = inet_addr(IP);

    // Connect to the remote host.
    int con = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    if (con == -1)
    {
        perror("connect");
        close(sockfd);
        exit(1);
    }
    // Open the file that you want to send.
    FILE *fp = fopen(fileName, "rb");
    if (!fp)
    {
        perror("fopen sender");
        return -1;
    }

    // Read the contents of the file and send it over the socket.
    char buffer[MAX];
    size_t bytes_read;
    start = clock();
    printf("TCP/IPv4 Socket - start: %f\n", (float)start / CLOCKS_PER_SEC);
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), fp)) > 0)
    {
        send(sockfd, buffer, bytes_read, 0);
        bzero(buffer, MAX);
    }
    // Close the file and the socket.
    fclose(fp);
    close(sockfd);
    return 0;
}

int reciverTCP()
{
    // Create a socket.
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);

    // Bind the socket to a local address and port
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    {
        perror("bind");
        return -1;
    }

    // Put the socket into listening mode
    if (listen(sock_fd, 10) == -1)
    {
        perror("listen");
        return -1;
    }

    // Accept incoming connections
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
    // receive data on the socket
    char buf[MAX];
    size_t num_bytes_received;
    size_t num_bytes_written;
    while ((num_bytes_received = recv(client_fd, buf, sizeof(buf), 0)) > 0)
    {
        num_bytes_written = fwrite(buf, sizeof(char), num_bytes_received, file);
        bzero(buf, MAX);
    }

    if (num_bytes_received == -1)
    {
        perror("recive");
        return -1;
    }
    close(sock_fd);
    // close(client_fd);
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

int sendTCP()
{
    int pid = fork();
    if (pid < 0)
    {
        return -1;
    }
    if (pid == 0)
    {
        senderTCP();
        exit(0);
    }
    else
    {
        reciverTCP();
        wait(NULL);
    }
}

/* UDP */
int reciverUDP()
{
    int sockfd;
    char buffer[MAX];
    struct sockaddr_in servaddr, cliaddr;

    // Creating socket file descriptor
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));
    memset(buffer, 0, MAX);
    // Filling server information
    servaddr.sin_family = AF_INET; // IPv4
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(12345);

    // Bind the socket with the server address
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

    int len = sizeof(cliaddr); // len is value/result
    size_t num_bytes_received;
    size_t num_bytes_written;
    while ((num_bytes_received = recvfrom(sockfd, (char *)buffer, MAX,
                                          MSG_WAITALL, (struct sockaddr *)&cliaddr,
                                          &len)) > 0)
    {
        if (num_bytes_received == -1)
        {
            perror("recive");
            return -1;
        }
        // printf("rec: %ld", num_bytes_received);
        num_bytes_written = fwrite(buffer, sizeof(char), num_bytes_received, file);
        // printf("write: %ld\n", num_bytes_written);
        bzero(buffer, MAX);
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

int senderUDP()
{
    int sockfd;
    char buffer[MAX];
    struct sockaddr_in servaddr;

    // Creating socket file descriptor
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    memset(buffer, 0, MAX);
    // Filling server information
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(12345);
    servaddr.sin_addr.s_addr = INADDR_ANY;

    // Open the file that you want to send.
    FILE *fp = fopen(fileName, "rb");
    if (!fp)
    {
        perror("fopen sender");
        return -1;
    }

    // Read the contents of the file and send it over the socket.
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
        bzero(buffer, MAX);
    }
    sendto(sockfd, "", 0, 0, (const struct sockaddr *)&servaddr, sizeof(servaddr));
    // Close the file and the socket.
    fclose(fp);
    close(sockfd);
    return 0;}


int sendUDP()
{
    int pid = fork();
    if (pid < 0){
        return ERROR;}
    if (pid == 0){
        senderUDP();
        exit(0);}
    else{
        reciverUDP();}
}

/* UDS strem */
int muser_the_UDS_stream(){ 
    int bytes_rec = 0;
    struct sockaddr_un muser_sockaddr;
    struct sockaddr_un sender_sockaddr;
    char buf[MAX];
   
    memset(&muser_sockaddr, 0, sizeof(struct sockaddr_un));
    memset(&sender_sockaddr, 0, sizeof(struct sockaddr_un));
    memset(buf, 0, MAX);

    int muser_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (muser_sock == -1){ // error in the socket
        printf("proble in the socket of Rcive UDS stream");
        exit(1);}
    
    muser_sockaddr.sun_family = AF_UNIX;
    strcpy(muser_sockaddr.sun_path, SOCK_PATH);
    int len = sizeof(muser_sockaddr);

    unlink(SOCK_PATH);
    int reciv = bind(muser_sock, (struct sockaddr *)&muser_sockaddr, len);
    if (reciv == ERROR){ // creat bind cetwen the soket and the local addres
        close(muser_sock);
        printf("prbloms with the bind in Recivr UDS stream");
        exit(1);}

    int backlog = 20;// the num of connecsion reqwest can be in the line to get in.
    reciv = listen(muser_sock, backlog); // lisen to the socket how wont to get connecsion
    if (reciv == ERROR){ // if he faild to lisen the socket
        close(muser_sock);
        printf("prbloms with the listen in Recivr UDS stream");
        exit(1);}
    int sender_sock = accept(muser_sock, (struct sockaddr *)&sender_sockaddr, &len); // recive the soket from the sender
    if (sender_sock == ERROR){ // if there was robles to in the accept
        close(muser_sock);
        close(sender_sock);
        printf("prbloms with the accept in Recivr UDS stream");
        exit(1);}
    len = sizeof(sender_sockaddr);
    reciv = getpeername(sender_sock, (struct sockaddr *)&sender_sockaddr, &len); //Put the address of the peer connected to socket sender into sender_sockaddr;
    if (reciv == ERROR){
        close(muser_sock);
        close(sender_sock);
        printf("prbloms with the getpeername in Recivr UDS stream");
        exit(1);}
    
    FILE *file_reciv = fopen("reciv_uds_file.txt", "wb"); // open file
    if (file_reciv == NULL){//cant open the file
        perror("prbloms with the open file in Recivr UDS stream");
        return ERROR;}
    
    unsigned long n_b_r;
    unsigned long n_b_w;
    while ((n_b_r = recv(sender_sock, buf, sizeof(buf), 0)) > 0){
        n_b_w = fwrite(buf, sizeof(char), n_b_r, file_reciv);
        bzero(buf, MAX);}
    
    if (n_b_r == ERROR){
        perror("prbloms with the recv in Recivr UDS stream");
        return ERROR;}
    fclose(file_reciv);
    chak_sum_UDS("reciv_uds_file.txt",end);
    close(muser_sock);
    close(sender_sock);
    return 0;
}
void chak_sum_UDS(char* file, clock_t end){
    end = clock();
    int check_sum = checkSum(file);
    if (check_sum == 1){
        printf("The end time of UDS stream soket: %f\n", (double)end / CLOCKS_PER_SEC);}
    else if (check_sum == ERROR){
        printf("The end time of UDS stream soket: -1 ther was a problem in the checksum\n");}}

int senderUDS_stream(){
    struct sockaddr_un muser_sockaddr;
    struct sockaddr_un sender_sockaddr;
    char buf[MAX];
    memset(&muser_sockaddr, 0, sizeof(struct sockaddr_un));
    memset(&sender_sockaddr, 0, sizeof(struct sockaddr_un));
    memset(buf, 0, MAX);
   
    int sender_sock = creat_socket_for_senderUDS();
    if (sender_sock == ERROR){
        printf("prbloms with the creat_socket in senderUDS_stream");
        exit(1);}
    
    sender_sockaddr.sun_family = AF_UNIX;
    strcpy(sender_sockaddr.sun_path, CLIENT_PATH);
    int len = sizeof(sender_sockaddr);
    unlink(CLIENT_PATH);

    int reciv = bind(sender_sock, (struct sockaddr *)&sender_sockaddr, len);
    if (reciv == ERROR){
        printf("prbloms with the bind in senderUDS_stream");
        close(sender_sock);
        exit(1);}

    muser_sockaddr.sun_family = AF_UNIX;
    strcpy(muser_sockaddr.sun_path, SERVER_PATH);
    reciv = connect(sender_sock, (struct sockaddr *)&muser_sockaddr, len);
    if (reciv == ERROR){
        printf("prbloms with the connect in  senderUDS_stream");
        close(sender_sock);
        exit(1);}

    FILE *file_sender = fopen(fileName, "rb");
    if (file_sender == NULL){
        perror("prbloms with the open file in  senderUDS_stream");
        return ERROR;}

    unsigned long b_r;
    clock_t start_time = clock();
    printf("The start time of UDS Stream socket: %f\n", (double)start_time / CLOCKS_PER_SEC);
    while ((b_r = fread(buf, 1, sizeof(buf), file_sender)) > 0){
        send(sender_sock, buf, b_r, 0);
        bzero(buf, MAX);}
    
    fclose(file_sender);
    close(sender_sock);

    return 0;
}

int creat_socket_for_senderUDS(){
    int a = socket(AF_UNIX, SOCK_STREAM, 0);
    return a;}

int sender_UDS_stream(){
    int pid = fork();
    if (pid < 0){
        return ERROR;}
    if (pid == 0){
        senderUDS_stream();
        exit(0);}
    else{
        muser_the_UDS_stream();}}

/* UDS datagram */
int muser_UDS_datagram(){
    struct sockaddr_un muser_sockaddr;
    char buf[MAX];
    memset(&muser_sockaddr, 0, sizeof(struct sockaddr_un));
    memset(buf, 0, MAX);

    int muser_sock = creat_socket_for_muser_UDS_datagram();
    if (muser_sock == ERROR){
        printf("prbloms with the creat soket in muser_UDS_datagram");
        exit(1);}
   
    muser_sockaddr.sun_family = AF_UNIX;
    strcpy(muser_sockaddr.sun_path, SOCK_PATH);
    int len = sizeof(muser_sockaddr);
    unlink(SOCK_PATH);

    int reciv = bind(muser_sock, (struct sockaddr *)&muser_sockaddr, len);
    if (reciv == ERROR){
        printf("prbloms with the bind in muser_UDS_datagram");
        close(muser_sock);
        exit(1);}
    
    FILE *file_recive = fopen("reciv_file_uds_diegram.txt", "wb");
    if (file_recive == NULL){
        perror("prbloms with the creat file in muser_UDS_datagram");
        return -1;
    }
   
   unsigned long bytes_rec = 0;

    while ((bytes_rec = recvfrom(muser_sock, (char *)buf, sizeof(buf), MSG_WAITALL, (struct sockaddr *)&muser_sockaddr, &len)) > 0)
    {
        if (bytes_rec == ERROR){
            printf("prbloms with the recvfrom in muser_UDS_datagram");
            close(muser_sock);
            exit(1);}
        else{
            fwrite(buf, sizeof(char), bytes_rec, file_recive);
            bzero(buf, MAX);}
    }
    int check_Sum = checkSum("reciv_file_uds_diegram.txt");
    chak_sum_muser_UDS(check_Sum,end);
    fclose(file_recive);
    close(muser_sock);
    return 0;
}

void chak_sum_muser_UDS(int check_Sum, clock_t end_time){
    end_time = clock();
    if (check_Sum == 1){
        printf("The end time of UDS Dgram socket is: %f\n", (double)end_time / CLOCKS_PER_SEC);}
    else if (check_Sum == ERROR){
        printf("The end time of UDS Dgram socket: -1 ther was a problem in the checksum\n");
    }}
int creat_socket_for_muser_UDS_datagram(){
    int a = socket(AF_UNIX, SOCK_DGRAM, 0);
    return a;}

int senderUDS_datagram()
{
    int client_sock, rc;
    struct sockaddr_un remote;
    char buf[MAX];
    memset(&remote, 0, sizeof(struct sockaddr_un));
    memset(buf, 0, MAX);
    
    client_sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (client_sock == -1)
    {
        printf("SOCKET ERROR");
        exit(1);
    }

 
    remote.sun_family = AF_UNIX;
    strcpy(remote.sun_path, SERVER_PATH);

    

    // Open the file that you want to send.
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
            bzero(buf, MAX);
        }
    }
    sendto(client_sock, "", 0, 0, (struct sockaddr *)&remote, sizeof(remote));

   
    fclose(fp);
    close(client_sock);

    return 0;
}

int sendUDS_datagram()
{
    int pid = fork();
    if (pid < 0){
        return ERROR;}
    if (pid == 0){
        senderUDS_datagram();
        exit(0);}
    else{
        muser_UDS_datagram();
        wait(NULL);}
}

int myMmap()
{

    int fd = open(fileName, O_RDWR);
    if (fd == -1)
    {
        perror("open");
        exit(1);
    }
    // Get the size of the file
    struct stat st;
    fstat(fd, &st);
    size_t filesize = st.st_size;

    // Map the file to memory
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

int myPipe()
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
        close(filedes[0]); // Child process does not need this end of the pipe

        /* Send "string" through the output side of pipe */
        char buf[MAX];
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
        /* Parent process closes up output side of pipe */
        close(filedes[1]); // Parent process does not need this end of the pipe

        FILE *file = fopen("rec_file_pipe.txt", "wb");
        if (file == NULL)
        {
            perror("reciver file");
            return -1;
        }
        char readbuffer[MAX];
        size_t num_bytes_received;
        /* Read in a string from the pipe */
        while (num_bytes_received = read(filedes[0], readbuffer, sizeof(readbuffer)))
        {

            fwrite(readbuffer, sizeof(char), num_bytes_received, file);
            bzero(readbuffer, MAX);
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

void *senderSharred_thread1(void *arg)
{
    // Get the address of the shared memory object from the argument
    void *addr = (void *)arg;
    // const char *filename = "100mb.txt";
    struct stat file_stat;
    if (stat(fileName, &file_stat) != 0)
    {
        perror("Error getting file information");
        exit(1);
    }

    // Print the size of the file
    // Transfer the file from the shared memory object to the specified location
    int dest_fd = open("rec_file_shared.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dest_fd == -1)
    {
        perror("OPEN");
        exit(1);
    }

    // Write the file from the shared memory object to the destination file
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

    // Return success
    return NULL;
}

void *senderSharred_thread2()
{
    start = clock();
    printf("SHARED MEMORY - start: %f\n", (double)start / CLOCKS_PER_SEC);

    int fd = open(fileName, O_RDONLY);

    size_t file_size = lseek(fd, 0, SEEK_END);

    void *addr = mmap(NULL, file_size, PROT_READ, MAP_SHARED, fd, 0);

    pthread_t thread;
    pthread_create(&thread, NULL, senderSharred_thread1, addr);
    
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


    // Return success
    return NULL;
}

void threads_shared_mem()
{
    pthread_t thread;
    pthread_create(&thread, NULL, senderSharred_thread2, fileName);

    // Wait for the thread to finish
    pthread_join(thread, NULL);
}

int main(int argc, char *argv[])
{
    create100MBBinaryFile();
    sendTCP();
    sender_UDS_stream();
    sendUDP();
    sendUDS_datagram();
    myMmap();
    myPipe();
    threads_shared_mem();
    return 0;
}
