#include<stdio.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<string.h>
#include "crypto_math.h"
#include "HW1.h"
#include<arpa/inet.h>
#include<unistd.h>
#include<sys/select.h>
#include<sys/types.h>
#include<sys/time.h>

void do_encrypt(char* plain, char* dest, int num_bytes, int key)
{
    int i = 0;
    while(i < num_bytes)
    {
        int plain_text = plain[i] & 255;
        int result = encrypt(plain_text, key);
        dest[i] = result & 255;
        //printf("ENCRYPTED %d to %d Using %d\n", plain_text, result, key);
        i++;
    }
}

void do_decrypt(char* plain, char* dest, int num_bytes, int key)
{
    int i = 0;
    while(i < num_bytes)
    {
        int encrypt_text = plain[i] & 255;
        int result = decrypt(encrypt_text, key);
        dest[i] = result & 255;
        i++;
    }
}

u_int make_key(char** name_buf, int comm_sock, u_int p, u_int root)
{
    u_int secret = rand() % p;
    u_int public = exp_mod(root, secret, p);
    u_int other_pub;
    unsigned char buf[524];
    unsigned char encrypt_buf[1024];
    char name[256];
    int byte_count = recv(comm_sock, name, 255, 0);
    name[byte_count]  = '\0';
    printf("RECIEVED CONNECTION FROM %s\n", name);
    memcpy(buf, &p, 4);
    memcpy(&buf[4], &root, 4);
    memcpy(&buf[8], &public, 4);
    
    byte_count = send(comm_sock, buf, 12, 0);
    
    byte_count = recv(comm_sock, &other_pub, 4, 0);
    
    u_int key = exp_mod(other_pub, secret, p);
    printf("CREATED KEY with %s: %u\n", name, key);
    strcpy(*name_buf, name);
    return key;
}

int main()
{
    int j;
    srand(787);
    // printf("GOT HERE\n");
    u_int prime = generate_prime(0);
    int * factors;
    int size;
    u_int p_root = find_prime_root(prime, &factors, &size);
    u_int otherPrime;
    prime_root_find:
    //printf("GENERATED PRIME\n");
    otherPrime = generate_prime(prime);
    int k;
    for(k = 0; k < size; k++)
    {
        if(otherPrime == factors[k])
        {
            goto prime_root_find;
        }
    }
    p_root = exp_mod(p_root, otherPrime, prime);
    //printf("GENERATED PRIMITIVE ROOT\n");
    
    unsigned char buf[1024];
    int c = 0;
    int i;
    int byte_count;
    socklen_t stuff;
    int listener;
    int socks[2];
    //int pipefd[2];
    struct sockaddr_in user[2];
    struct sockaddr_in self;
    listener = socket(AF_INET, SOCK_STREAM, 0);
    memset(&self, '\0', sizeof(self));
    self.sin_family = AF_INET;
    self.sin_port = htons(4625);
    inet_pton(AF_INET, "127.0.0.1", &self.sin_addr);
    
    bind(listener, (struct sockaddr*) &self, sizeof(self));
    listen(listener, 2);
    //pipe(pipefd);
    
    char* names[2];
    u_int keys[2];
    for(i = 0; i<2; i++)
        names[i] = malloc(256);
    
    while(c < 2) // Accept communicating parties and create keys using diffie helman
    {
        printf("READY TO ACCEPT CONNECTIONS\n");
        socks[c] = accept(listener, (struct sockaddr*) &user[c], &stuff);
        
        //int p = fork();
        //if(p == 0)
        //{
        //    close(pipefd[0]);
        keys[c] = 1023 & make_key(&names[c], socks[c], prime, p_root);
        //}
        c++;
    }
    /*
    c = 0;
    while(c < 2) // recieve key and name info from children
    {
        byte_count = recv(pipefd[0], buf, 260, 0);
        strcpy(names[c], buf);
        i = strlen(names[c]);
        memcpy(&keys[c], &buf[i+1], 4);
        keys[c] = keys[c] & 1023;
        c++;
    }
    */
    printf("Parent recieved key information for clients from children:\n");
    for(c=0; c<2; c++)
    {
        printf("CLIENT %s: %u\n", names[c], keys[c]);
    }
    
    //close(pipefd[0]);
    //close(pipefd[1]);
    close(listener);
    
    fd_set reading;
    FD_ZERO(&reading);
    FD_SET(socks[0], &reading);
    FD_SET(socks[1], &reading);
    
    int max = socks[0];
    if(socks[1] > socks[0])
        max = socks[1];
        
    printf("LISTENING FOR CONNECTION REQUEST\n");
    int ready = select(max+1, &reading, NULL, NULL, NULL);
    int sender, reciever;
    if(FD_ISSET(socks[0], &reading))
    {
        sender = 0;
        reciever = 1;
    }
    else
    {
        sender = 1;
        reciever = 0;
    }
    byte_count = recv(socks[sender], buf, 520, 0);
    printf("RECIEVED %d bytes\n", byte_count);
    
    char send_c[256]; 
    char recv_c[256];
    u_int nonce;
    strcpy(send_c, buf);
    //printf("RECIEVED SENDER ID %s\n", send_c);
    i = strlen(send_c);
    strcpy(recv_c, &buf[i+1]);
    //printf("RECIEVED RECIEVER ID %s\n", recv_c);
    c = strlen(recv_c);
    
    memcpy(&nonce, &buf[i+c+2], 4);
    printf("RECIEVED NONCE VAL %u\n", nonce); 
    // should do some verification here, don't currently
    
    u_int session = rand();
    printf("SESSION KEY: %u\n", session);
    unsigned char encrypt_buf[1024];
    memset(encrypt_buf, 0, 200);
    
    memcpy(buf, &session, 4);
    strcpy(&buf[4], recv_c);
    memcpy(&buf[5+c], &nonce, 4);
    memcpy(&buf[9+c], &session, 4);
    strcpy(&buf[13+c], send_c);
    memcpy(&buf[14+c+i], &nonce, 4);
    
    do_encrypt((char *) &buf[9+c], (char* ) &encrypt_buf[9+c], i+9, keys[reciever]);
    for(j = 0; j< 18+i+c; j++)
    {
        printf("%u ", buf[j]);
    }
    printf("\n");
    
    memcpy(&buf[9+c], &encrypt_buf[9+c], i+9);
    printf("\n");
    do_encrypt((char *) buf, (char *) encrypt_buf, i+c+18, keys[sender]);
    for(j = 0; j< 18+i+c; j++)
    {
        printf("%u ", encrypt_buf[j]);
    }
    send(socks[sender], encrypt_buf, i+c+18, 0);
    printf("SENT ENCRYPTED MESSAGE\n");
    
    return 0;
}
