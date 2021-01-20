#ifndef INTERCEPT_H
#define INTERCEPT_H

#include <stdint.h>
#include "network.h"

#define BUFFER_SIZE 65536
#define ICMP 1
#define TCP 6
#define UDP 17

struct eth_frame* parse_frame(const uint8_t*, const unsigned int);
char* format_mac(char[18], const uint8_t[6]);
char* format_ip(char[16], const uint8_t[4]);
void print_frame(const struct eth_frame*);
void print_packet(const struct ipv4_packet*);
void print_icmp(const struct ipv4_packet*);
void print_tcp(const struct ipv4_packet*);
void print_udp(const struct ipv4_packet*);
void print_payload(const uint8_t*);
#endif
