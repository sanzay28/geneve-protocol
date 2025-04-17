#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

#include "geneve.h"

#define MIN_PAYLOAD_SIZE 64
#define MAX_PAYLOAD_SIZE 1500

struct eth_header {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
} __attribute__((packed));



volatile int keep_running = 1;
geneve_socket_t4 *g_sock;


void handle_signal(int sig) 
{
    (void)sig;
    printf("\nStopping...\n");
    keep_running = 0;
    geneve_close4(g_sock);
    exit(0);
}


void *send_packets(void *arg) 
{
    (void)arg;
    srand(time(NULL));

    while (keep_running) {
        
        int payload_size = (rand() % (MAX_PAYLOAD_SIZE - MIN_PAYLOAD_SIZE + 1)) + MIN_PAYLOAD_SIZE;
        unsigned char *payload = malloc(payload_size);   // dynamically alocating memory for payload.
        if (!payload) {
            perror("Memory allocation failed");
            continue;
        }

        
        for (int i = 0; i < payload_size; i++) {
            payload[i] = rand() % 256;      // the payload will be ranging from 64 to 1500
        }

        
        struct ethhdr eth;
        memset(&eth, 0, sizeof(struct ethhdr));
        eth.h_source[0] = 0x00; eth.h_source[1] = 0x11; eth.h_source[2] = 0x22;
        eth.h_source[3] = 0x33; eth.h_source[4] = 0x44; eth.h_source[5] = 0x55;
        eth.h_dest[0] = 0x66; eth.h_dest[1] = 0x77; eth.h_dest[2] = 0x88;
        eth.h_dest[3] = 0x99; eth.h_dest[4] = 0xAA; eth.h_dest[5] = 0xBB;
        eth.h_proto = htons(ETH_P_IP);

        // IP Header
        struct iphdr ip;
        memset(&ip, 0, sizeof(struct iphdr));
        ip.version = 4;
        ip.ihl = 5;
        ip.tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + payload_size);
        ip.ttl = 64;
        ip.protocol = IPPROTO_UDP;
        ip.saddr = inet_addr("10.22.148.241");
        ip.daddr = inet_addr("10.22.156.182");

        // UDP Header
        struct udphdr udp;
        memset(&udp, 0, sizeof(struct udphdr));
        udp.source = htons(50000);
        udp.dest = htons(50001);
        udp.len = htons(sizeof(struct udphdr) + payload_size);

        // Construct full packet
        int packet_size = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + payload_size;
        unsigned char *packet = malloc(packet_size);
        if (!packet) {
            perror("Packet memory allocation failed");
            free(payload);
            continue;
        }

        memcpy(packet, &eth, sizeof(struct ethhdr));
        memcpy(packet + sizeof(struct ethhdr), &ip, sizeof(struct iphdr));
        memcpy(packet + sizeof(struct ethhdr) + sizeof(struct iphdr), &udp, sizeof(struct udphdr));
        memcpy(packet + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr), payload, payload_size);

        // Send encapsulated packet
        printf("Sending GENEVE packet (Payload size: %d bytes)...\n", payload_size);
        geneve_write4(g_sock, packet, packet_size);

        free(packet);
        free(payload);
        sleep(2);
    }

    return NULL;
}

void *receive_packets(void *arg)
{	
	(void)arg;
	geneve_read4(g_sock);
	return NULL;
}


int main(int argc, char *argv[]) 
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <local_ip> <remote_ip>\n", argv[0]);
        return EXIT_FAILURE;
    }

    //char *local_ip = argv[1];
    char *remote_ip = argv[2];      // source des

    signal(SIGINT, handle_signal);

    g_sock = geneve_socket4(AF_INET, remote_ip, 1001);
    if (!g_sock) {
        fprintf(stderr, "Failed to create GENEVE socket\n");
        return EXIT_FAILURE;
    }

    pthread_t send_thread, recv_thread;
    
    pthread_create(&send_thread, NULL, send_packets, NULL);
    pthread_create(&recv_thread, NULL, receive_packets, NULL);

    pthread_join(send_thread, NULL);
    pthread_join(recv_thread, NULL);

 
   return 0;
}
