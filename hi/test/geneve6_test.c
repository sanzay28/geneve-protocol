#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <unistd.h>


#include "geneve.h"

#define MIN_PAYLOAD_SIZE 64
#define MAX_PAYLOAD_SIZE 1500

struct eth_header {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
} __attribute__((packed));


volatile int keep_running = 1;
geneve_socket_t6 *g_sock;

void handle_signal(int sig) 
{
    (void)sig;
    printf("\nStopping...\n");
    keep_running = 0;
    geneve_close6(g_sock);
    exit(0);
}

void *send_packets(void *arg) 
{
    (void)arg;
    srand(time(NULL));

    while (keep_running) {
        int data_len = (rand() % (MAX_PAYLOAD_SIZE - MIN_PAYLOAD_SIZE + 1)) + MIN_PAYLOAD_SIZE;
        int total_len = 14 + 40 + 8 + data_len; // Eth + Inner IPv6 + UDP + Data

        unsigned char *packet = malloc(total_len);
        if (!packet) {
            perror("Memory allocation failed");
            continue;
        }

        
        memset(packet, 0, total_len);
        
	packet[0] = 0x00; packet[1] = 0x1A; packet[2] = 0x2B;
	packet[3] = 0x3C; packet[4] = 0x4D; packet[5] = 0x5E;

	
	packet[6] = 0x02; packet[7] = 0xAA; packet[8] = 0xBB;
	packet[9] = 0xCC; packet[10] = 0xDD; packet[11] = 0xEE;

        packet[12] = 0x86; packet[13] = 0xDD;  

       
        packet[14] = 0x60;  
        uint16_t payload_len = htons(8 + data_len);  
        memcpy(&packet[18], &payload_len, 2);        
        packet[20] = 17;  
        packet[21] = 64;  

        
        struct in6_addr src_addr, dst_addr;
        inet_pton(AF_INET6, "fe80::759e:df4d:9360:79a2", &src_addr);
        inet_pton(AF_INET6, "fe80::de9a:f78:6230:6537", &dst_addr);
        memcpy(&packet[22], &src_addr, 16);
        memcpy(&packet[38], &dst_addr, 16);

        
        uint16_t src_port = htons(12345);
        uint16_t dst_port = htons(54321);
        uint16_t udp_len = htons(8 + data_len);
        memcpy(&packet[54], &src_port, 2);
        memcpy(&packet[56], &dst_port, 2);
        memcpy(&packet[58], &udp_len, 2);

        
        for (int i = 0; i < data_len; ++i) {
            packet[62 + i] = rand() % 256;
        }

        
        struct {
            struct in6_addr src;
            struct in6_addr dst;
            uint32_t len;
            uint8_t zero[3];
            uint8_t next_hdr;
            uint16_t src_port;
            uint16_t dst_port;
            uint16_t length;
            uint16_t checksum;
        } __attribute__((packed)) pseudo_header;

        memset(&pseudo_header, 0, sizeof(pseudo_header));
        memcpy(&pseudo_header.src, &src_addr, 16);
        memcpy(&pseudo_header.dst, &dst_addr, 16);
        pseudo_header.len = htonl(8 + data_len);
        pseudo_header.next_hdr = 17;
        pseudo_header.src_port = src_port;
        pseudo_header.dst_port = dst_port;
        pseudo_header.length = udp_len;

        uint8_t checksum_buffer[sizeof(pseudo_header) + 8 + data_len];
        memcpy(checksum_buffer, &pseudo_header, sizeof(pseudo_header));
        memcpy(checksum_buffer + sizeof(pseudo_header), packet + 54, 8 + data_len);

        uint16_t udp_checksum = compute_udp_checksum6(checksum_buffer, sizeof(checksum_buffer));
        memcpy(&packet[60], &udp_checksum, 2);

        
        printf("Sending GENEVE packet with payload: %d bytes (including headers)\n", total_len - 14);
        geneve_write6(g_sock, packet + 14, total_len - 14);  

        free(packet);
        sleep(2);
    }

    return NULL;
}



void *receive_packets(void *arg)
{	
	(void)arg;
	geneve_read6(g_sock);
	return NULL;
}



int main(int argc, char *argv[]) 
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <local_ipv6> <remote_ipv6>\n", argv[0]);
        return EXIT_FAILURE;
    }

    	pthread_t send_thread, recv_thread;

	signal(SIGINT, handle_signal);

	g_sock = geneve_socket6("fe80::de9a:f78:6230:6537", 1001);
	if (!g_sock) {
    	fprintf(stderr, "Failed to create GENEVE socket\n");
    		return 1;
	}

	pthread_create(&send_thread, NULL, send_packets, NULL);
	usleep(2000000);
	pthread_create(&recv_thread, NULL, receive_packets, NULL);

	pthread_join(send_thread, NULL);
	pthread_join(recv_thread, NULL);

    return EXIT_SUCCESS;
}
