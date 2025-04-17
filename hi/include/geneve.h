#ifndef GENEVE_H
#define GENEVE_H

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>



// GENEVE Header Structure
struct geneve_header 
{
    uint8_t version_flags;  
    uint8_t opt_len_proto;  
    uint16_t protocol;    
    uint32_t vni_reserved;  
} __attribute__((packed));


// ipv4
typedef struct 
{
    int sock4;
    struct sockaddr_in dest_addr4;
} geneve_socket_t4;


//ipv6
typedef struct 
{
    int sock6;
    struct sockaddr_in6 dest_addr6;
} geneve_socket_t6;

// ipv4
geneve_socket_t4 *geneve_socket4(int af, const char *dst_ip, uint32_t vni);
ssize_t geneve_write4(geneve_socket_t4 *g_sock, const void *buffer, size_t len);
void geneve_read4(geneve_socket_t4 *g_sock);
void geneve_close4(geneve_socket_t4 *g_sock);

//ipv6
geneve_socket_t6 *geneve_socket6(const char *dst_ip, uint32_t vni);
ssize_t geneve_write6(geneve_socket_t6 *g_sock, const void *buffer, size_t len);
void geneve_read6(geneve_socket_t6 *g_sock);
uint16_t compute_udp_checksum6(const uint8_t *pseudo_header, size_t len);
void geneve_close6(geneve_socket_t6 *g_sock);

#endif
