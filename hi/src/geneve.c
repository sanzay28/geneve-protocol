#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/udp.h>


#include "geneve.h"


#define BUFFER_SIZE 2048



uint16_t compute_udp_checksum6(const uint8_t *pseudo_header, size_t len) 
{
    uint32_t sum = 0;
    const uint16_t *data = (const uint16_t *)pseudo_header;

    
    for (size_t i = 0; i < len / 2; i++) {
        sum += ntohs(data[i]);
        if (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16); 
        }
    }

    
    if (len % 2) {
        sum += (pseudo_header[len - 1] << 8);
        if (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }

    return htons(~sum);  
}



geneve_socket_t4 *geneve_socket4(int af, const char *dst_ip, uint32_t vni) 
{
    (void)vni;
    

    geneve_socket_t4 *g_sock = (geneve_socket_t4 *)malloc(sizeof(geneve_socket_t4));
    if (!g_sock) {
        perror("malloc failed");
        return NULL;
    }

    g_sock->sock4 = socket(af, SOCK_DGRAM, 0);
    if (g_sock->sock4 < 0) {
        perror("socket creation failed");
        free(g_sock);
        return NULL;
    }

    memset(&g_sock->dest_addr4, 0, sizeof(g_sock->dest_addr4));
    g_sock->dest_addr4.sin_family = af;
    g_sock->dest_addr4.sin_port = htons(6081);
    inet_pton(af, dst_ip, &g_sock->dest_addr4.sin_addr);

    return g_sock;
}

geneve_socket_t6 *geneve_socket6(const char *dst_ip, uint32_t vni) 
{
    (void)vni;
    geneve_socket_t6 *g_sock = (geneve_socket_t6 *)malloc(sizeof(geneve_socket_t6));
    if (!g_sock) {
        perror("malloc failed");
        return NULL;
    }

    g_sock->sock6 = socket(AF_INET6, SOCK_DGRAM, 0);
    if (g_sock->sock6 < 0) {
        perror("Socket creation failed");
        free(g_sock);
        return NULL;
    }

    memset(&g_sock->dest_addr6, 0, sizeof(g_sock->dest_addr6));
    g_sock->dest_addr6.sin6_family = AF_INET6;
    g_sock->dest_addr6.sin6_port = htons(6081);
    
    if (inet_pton(AF_INET6, dst_ip, &g_sock->dest_addr6.sin6_addr) != 1) {
        perror("Invalid IPv6 address");
        free(g_sock);
        return NULL;
    }
    g_sock->dest_addr6.sin6_scope_id = if_nametoindex("enp3s0");

    return g_sock;
}

ssize_t geneve_write4(geneve_socket_t4 *g_sock, const void *buffer, size_t len)
{
    int ret = 0;
    
    if (!g_sock) {
        errno = EINVAL;
        return -1;
    }
    printf("Sending packet: %zu bytes\n", len);


    struct geneve_header geneve_hdr = {0};
    geneve_hdr.version_flags = 0x00;
    geneve_hdr.opt_len_proto = 0x00;
    geneve_hdr.protocol = htons(0x6558);
    geneve_hdr.vni_reserved = htonl(1001 << 8);

    uint8_t packet[sizeof(struct geneve_header) + len];
    memcpy(packet, &geneve_hdr, sizeof(struct geneve_header));
    memcpy(packet + sizeof(struct geneve_header), buffer, len);

    ret = sendto(g_sock->sock4, packet, sizeof(packet), 0,
                  (struct sockaddr *)&g_sock->dest_addr4, sizeof(g_sock->dest_addr4));
                  
    printf("%s:%d ret %d", __func__, __LINE__, ret);
    
    return ret;
}

ssize_t geneve_write6(geneve_socket_t6 *g_sock, const void *buffer, size_t len)
{
    if (!g_sock) {
        errno = EINVAL;
        return -1;
    }

    printf("Sending IPv6 GENEVE packet: %zu bytes\n", len);

    struct geneve_header geneve_hdr = {0};
    geneve_hdr.version_flags = 0x00;
    geneve_hdr.opt_len_proto = 0x00;
    geneve_hdr.protocol = htons(ETH_P_IPV6); 
    geneve_hdr.vni_reserved = htonl(1001 << 8);

    
    uint8_t packet[sizeof(struct geneve_header) + len];
    memcpy(packet, &geneve_hdr, sizeof(struct geneve_header));
    memcpy(packet + sizeof(struct geneve_header), buffer, len);

    ssize_t ret = sendto(g_sock->sock6, packet, sizeof(packet), 0,
                         (struct sockaddr *)&g_sock->dest_addr6, sizeof(g_sock->dest_addr6));
    if (ret < 0) {
        perror("sendto failed");
    }

    return ret;
}

void geneve_read4(geneve_socket_t4 *g_sock) 
{
    if (!g_sock) {
        fprintf(stderr, "Invalid GENEVE socket\n");
        return;
    }

    int sock;
    struct sockaddr_in server_addr, client_addr;
    unsigned char buffer[BUFFER_SIZE];
    socklen_t addr_len = sizeof(client_addr);

    
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return;
    }


    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; 
    server_addr.sin_port = htons(6081);

    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(sock);
        return;
    }

    printf("GENEVE Receiver started. Listening on UDP port 6081...\n");

    while (1) 
    {
        ssize_t received_bytes = recvfrom(sock, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &addr_len);
        if (received_bytes < 0) {
            perror("recvfrom failed");
            continue;
        }

        // Extract GENEVE header
        if (received_bytes < (ssize_t)sizeof(struct geneve_header)) {
            printf("Received packet too small for GENEVE header\n");
            continue;
        }

        struct geneve_header *geneve_hdr = (struct geneve_header *)buffer;
        unsigned char *inner_packet = buffer + sizeof(struct geneve_header);

        printf("\nReceived GENEVE Packet - VNI: %u\n", ntohl(geneve_hdr->vni_reserved) >> 8);

        // Extract Ethernet header
        if (received_bytes < (ssize_t)(sizeof(struct geneve_header) + sizeof(struct ethhdr))) {
            printf("Packet too small for Ethernet header\n");
            continue;
        }

        struct ethhdr *inner_eth = (struct ethhdr *)inner_packet;
        printf("Inner Ethernet Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               inner_eth->h_source[0], inner_eth->h_source[1], inner_eth->h_source[2],
               inner_eth->h_source[3], inner_eth->h_source[4], inner_eth->h_source[5]);

        // Extract IP header
        size_t offset = sizeof(struct ethhdr);
        if (received_bytes < (ssize_t)(sizeof(struct geneve_header) + offset + sizeof(struct iphdr))) {
            printf("Packet too small for IP header\n");
            continue;
        }

        struct iphdr *inner_ip = (struct iphdr *)(inner_packet + offset);
        printf("Inner IP Src: %d.%d.%d.%d\n",
               inner_ip->saddr & 0xFF, (inner_ip->saddr >> 8) & 0xFF,
               (inner_ip->saddr >> 16) & 0xFF, (inner_ip->saddr >> 24) & 0xFF);

        // Extract UDP header
        offset += sizeof(struct iphdr);
        if (received_bytes < (ssize_t)(sizeof(struct geneve_header) + offset + sizeof(struct udphdr))) {
            printf("Packet too small for UDP header\n");
            continue;
        }

        struct udphdr *inner_udp = (struct udphdr *)(inner_packet + offset);
        printf("Inner UDP Src Port: %d\n", ntohs(inner_udp->source));
        printf("Inner UDP Dst Port: %d\n", ntohs(inner_udp->dest));

        // Extract payload
        offset += sizeof(struct udphdr);
        if (received_bytes > (ssize_t)(sizeof(struct geneve_header) + offset)) {
            uint8_t *payload = inner_packet + offset;
            size_t payload_size = received_bytes - (sizeof(struct geneve_header) + offset);

            printf("Inner Payload (%zu bytes, first 10 bytes): ", payload_size);
            for (size_t i = 0; i < payload_size && i < 10; i++) {
                printf("%02x ", payload[i]);
            }
            printf("\n");
        }
    }

    close(sock);
}

void geneve_read6(geneve_socket_t6 *g_sock) 
{
    if (!g_sock) {
        fprintf(stderr, "Invalid GENEVE socket\n");
        return;
    }

    int sock;
    struct sockaddr_in6 server_addr, client_addr;
    unsigned char buffer[BUFFER_SIZE];
    socklen_t addr_len = sizeof(client_addr);

    sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_addr = in6addr_any;
    server_addr.sin6_port = htons(6081);

    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(sock);
        return;
    }

    printf("GENEVE IPv6 Receiver started. Listening on UDP port 6081...\n");

    while (1) 
    {
        ssize_t received_bytes = recvfrom(sock, buffer, BUFFER_SIZE, 0,(struct sockaddr *)&client_addr, &addr_len);
        if (received_bytes < 0) {
            perror("recvfrom failed");
            continue;
        }

        if (received_bytes < (ssize_t)sizeof(struct geneve_header)) {
            printf("Received packet too small for GENEVE header\n");
            continue;
        }

        struct geneve_header *geneve_hdr = (struct geneve_header *)buffer;
        size_t inner_payload_size = received_bytes - sizeof(struct geneve_header);

        if (inner_payload_size > 0) {
            printf("Received inner packet of size: %zu bytes\n", inner_payload_size);
            // Process inner packet if needed
        }

        char client_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &client_addr.sin6_addr, client_ip, sizeof(client_ip));

        printf("\nReceived GENEVE IPv6 Packet from %s - VNI: %u\n",client_ip, ntohl(geneve_hdr->vni_reserved) >> 8);
    }

    close(sock);
}

void geneve_close4(geneve_socket_t4 *g_sock) 
{
    if (g_sock) {
        close(g_sock->sock4);
        free(g_sock);
    }
}


void geneve_close6(geneve_socket_t6 *g_sock) 
{
    if (g_sock) {
        close(g_sock->sock6);
        free(g_sock);
    }
}
