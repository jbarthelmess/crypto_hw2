#include<stdio.h>
#include "crypto_math.h"
#include<string.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<arpa/inet.h>
#include "HW1.h"
#include<unistd.h>

void do_encrypt(char* plain, char* dest, int num_bytes, int key)
{
    int i = 0;
    while(i < num_bytes)
    {
        int plain_text = plain[i] & 255;
        int result = encrypt(plain_text, key);
        dest[i] = result & 255;
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
        //printf("DECRYPTING %d to %d using %d\n", encrypt_text, result, key);
        i++;
    }
}

int main(int argc, char** argv)
{
    int top = 0;
    int q;
    // printf("%d\n", argc);
    if(argc < 4)
    {
        fprintf(stderr, "USAGE: ./a.out <NAME> <PORT> <KDC_PORT> [<CONNECTOR>]\n");
        return EXIT_FAILURE;
    }
    srand(strlen(argv[1])+argc);
    // First connect to KDC 
    int kdc = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in kdc_info;
    memset(&kdc_info, 0, sizeof(kdc_info));
    kdc_info.sin_family = AF_INET;
    kdc_info.sin_port = htons(atoi(argv[3]));
    inet_pton(AF_INET, "127.0.0.1", &kdc_info.sin_addr);
    
    top = connect(kdc, (struct sockaddr* ) &kdc_info, sizeof(kdc_info));
    if(top == -1)
    {
        perror("connect");
        return EXIT_FAILURE;
    }
    printf("GOT HERE\n");
    
    char name[256]; // HOLDS MY NAME
    unsigned char buf[1024]; // BUFFER FOR SEND AND RECV
    unsigned char encrypt_buf[1024];
    if(strlen(argv[1]) > 255)
    {
        fprintf(stderr, "NAME IS TOO LONG\n");
        return EXIT_FAILURE;
    }
    printf("NAME VERIFIED\n");
    // SEND KDC MY NAME AND IT WILL SEND DIFFIE HELMAN INFO
    strcpy(name, argv[1]);
    printf("COPIED NAME\n");
    top = send(kdc, name, strlen(name), 0);
    if(top == -1)
    {
        perror("send");
        exit(EXIT_FAILURE);
    }
    printf("NAME SENT\n");
    top = recv(kdc, buf, 12, 0); // RECV PRIME, ROOT, KDC_PUB All 32 bit ints
    if(top == -1)
    {
        perror("recv");
        exit(EXIT_FAILURE);
    }
    printf("%d\n", top);
    for(q = 0; q< top; q++)
    {
        printf("%u ", buf[q]);
    }
    printf("\n");
    // CREATE KEY
    u_int prime, root, kdc_pub;
    memcpy(&prime, buf, 4);
    memcpy(&root, &buf[4], 4);
    memcpy(&kdc_pub, &buf[8], 4);
    
    printf("RECIEVED KEY INFO\n");
    printf("%u\n", prime);
    /* PERFORM DIFFIE HELMAN TRICK, secret key is only used to get symmetric key*/
    u_int secret = rand() % prime; // Must be less than the prime
    u_int my_pub = exp_mod(root, secret, prime);
    memcpy(buf, &my_pub, 4);
    
    send(kdc, buf, 4, 0); // SEND PUBLIC KEY
    u_int key = exp_mod(kdc_pub, secret, prime); // CALCULATE SYMMETRIC KEY
    printf("CREATED KEY WITH SERVER: %u\n", key);
    
    key = key & 1023; // KEYS ARE 10 bits for TOY_DES
    printf("ACTUAL DECRYPTION KEY: %u\n", key);
    
    int connection = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in init;
    struct sockaddr_in other;
    memset(&init, 0, sizeof(init));
    memset(&other, 0, sizeof(other));
    socklen_t throwaway;
    int byte_count;
    int i;
    char other_name[256];
    u_int key_s;
    char input_check;
    
    if(argc == 5) // This will be the initiator of the convo
    {
        // Allows time to set up reciever if needed
        printf("PLEASE INPUT ANYTHING WHEN YOU ARE READY TO CONTINUE: ");
        scanf("%c", &input_check);
        
        // SEND UNENCRYPTED MESSAGE THAT I WANT TO TALK TO BOB
        printf("GETTING SESSION KEY FROM KDC\n");
        u_int nonce1 = rand();
        u_int check = 0;
        strcpy(other_name, argv[4]);
        strcpy(buf, name);
        strcpy(&buf[strlen(name)+1], other_name);
        memcpy(&buf[strlen(name)+strlen(other_name)+2], (unsigned char *)&nonce1, 4);
        byte_count = send(kdc, buf, strlen(name)+strlen(other_name)+6, 0);
        printf("SENT %d bytes\n", byte_count);
        // RECIEVE ENCRYPTED PACKETS
        byte_count = recv(kdc, encrypt_buf, strlen(name)+strlen(other_name)+18, 0);
        fflush(stdout);
        do_decrypt(encrypt_buf, buf, byte_count, key);
        
        // SAVE SESSION KEY AND DO NONCE CHECK
        memcpy(&key_s, buf, 4);
        memcpy(&check, &buf[strlen(other_name)+5], 4);
        if(check == nonce1)
            printf("NONCE CHECK SUCCESSFUL, SENDING TO %s\n", other_name);
        else
        {
            printf("NONCE CHECK UNSUCCESSFUL\nNONCE: %u\nNONCE_RET: %u\n", nonce1, check);
            exit(EXIT_FAILURE);
        }
        
        // CONNECT TO RECIEVER AND SEND ENCRYPTED PACKET
        unsigned char other_buf[1024];
        memcpy(other_buf, &buf[strlen(other_name)+9], strlen(name)+9);
        
        init.sin_port = htons(atoi(argv[2]));
        init.sin_family = AF_INET;
        inet_pton(AF_INET, "127.0.0.1", &init.sin_addr);
        printf("SETTING UP CONNECTION TO %s\n", other_name);
        top = connect(connection, (struct sockaddr* ) &init, sizeof(init));
        if(top == -1)
        {
            perror("connect");
            exit(EXIT_FAILURE);
        }
        send(connection, other_buf, strlen(name)+9, 0);
        printf("SENT ENCRYPTED PACKET, WAITING FOR RESPONSE\n");
        
        // RECEIVE SECOND NONCE PERFORM BITSHIFT AND SEND IT BACK ENCRYPTED
        recv(connection, buf, 4, 0);
        for(i = 0; i< 4; i++)
        {
            buf[i] = decrypt(buf[i], key_s);
        }
        memcpy(&check, buf, 4);
        u_int holder2 = 240;
        holder2 = holder2 << 24;
        holder2 = holder2 & check;
        check = check << 4;
        holder2 = holder2 >> 28;
        check = check + holder2;
        memcpy(buf, &check, 4);
        for(i = 0; i< 4; i++)
        {
            buf[i] = encrypt(buf[i], key_s);
        }
        printf("SENDING SHIFTED NONCE, SETUP COMPLETE\n");
        send(connection, buf, 4, 0);
    }
    else // This person will wait to be contacted
    {
        // SET UP LISTENING CONNECTION
        init.sin_port = htons(atoi(argv[2]));
        init.sin_family = AF_INET;
        inet_pton(AF_INET, "127.0.0.1", &init.sin_addr);
        
        bind(connection, (struct sockaddr* ) &init, sizeof(init));
        listen(connection, 2);
        printf("READY TO CONNECT TO OTHERS ON PORT %hu\n", atoi(argv[2]));
        int comm = accept(connection, (struct sockaddr*) &other, &throwaway);
        close(connection);
        
        // RECIEVE ENCRYPTED PACKET
        byte_count = recv(comm, buf, 264, 0);
        for(i = 0; i< byte_count; i++)
        {
            buf[i] = 255 & decrypt(buf[i], key);
        }
        
        memcpy(&key_s, buf, 4);
        key_s = key_s & 1023;
        
        strcpy(other_name, &buf[4]);
        printf("CONTACTED BY %s performing final verification\n", other_name);
        
        u_int nonce = rand();
        u_int nonce_ret;
        u_int holder;
        memcpy(buf, &nonce, 4);
        for(i=0; i< 4; i++)
        {
            buf[i] = 255 & encrypt(buf[i], key_s);
        }
        
        send(comm, buf, 4, 0);
        
        recv(comm, buf, 4, 0);
        
        for(i = 0; i< 4; i++)
        {
            buf[i] = 255 & decrypt(buf[i], key_s);
        }
        memcpy(&nonce_ret, buf, 4);
        printf("RECEIVED NONCE_RET: %u\n", nonce_ret);
        
        holder = nonce_ret & 15;
        
        nonce_ret = nonce_ret >> 4;
        nonce_ret = nonce_ret + (holder << 28);
        
        if(nonce_ret == nonce)
            printf("VERIFIED\n");
        else
        {
            printf("VERIFICATION FAILED\nNONCE: %u\nNONCE_RET: %u\n", nonce, nonce_ret);
        }
    }
    return 0;
}
