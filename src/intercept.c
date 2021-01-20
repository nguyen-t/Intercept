#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include "intercept.h"

struct eth_frame* parse_frame(const uint8_t* raw, const unsigned int length) {
  struct eth_frame* frame = malloc(length);

  memcpy(frame, raw, length);

  return frame;
}

char* format_mac(char dest[19], const uint8_t mac[6]) {

  snprintf(dest, 19, "%02X:%02X:%02X:%02X:%02X:%02X",
    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

  return dest;
}

char* format_ip(char dest[16], const uint8_t ip[4]) {
  snprintf(dest, 16, "%u.%u.%u.%u",
    ip[0], ip[1], ip[2], ip[3]);

  return dest;
}

void print_frame(const struct eth_frame* frame) {
  char dest[19];
  char src[19];

  format_mac(dest, frame->destination);
  format_mac(src, frame->source);

  printf("|-------------Ethernet Frame-------------|\n");
  printf("|%-20s%-20s|\n", "Destination:", dest);
  printf("|%-20s%-20s|\n", "Source:", src);
  printf("|%-20s%-20u|\n", "Ethertype:", frame->ethertype);
  printf("|%-40s|\n", "");
}

void print_packet(const struct ipv4_packet* packet) {
  char src[16];
  char dest[16];

  format_ip(src, packet->source);
  format_ip(dest, packet->destination);

  printf("|              IPv4 Packet               |\n");
  printf("|%-20s%-20u|\n", "Version:", packet->version);
  printf("|%-20s%-20u|\n", "Header Length:", packet->ihl);
  printf("|%-20s%-20u|\n", "Service", packet->service);
  printf("|%-20s%-20u|\n", "Total Length:", packet->total_length);
  printf("|%-20s%-20u|\n", "Identification:", packet->identification);
  printf("|%-20s%-20u|\n", "Zero:", packet->zero);
  printf("|%-20s%-20u|\n", "DF:", packet->df);
  printf("|%-20s%-20u|\n", "MF:", packet->mf);
  printf("|%-20s%-20u|\n", "Fragment Offset:", packet->fragment_offset);
  printf("|%-20s%-20u|\n", "Time-To-Live:", packet->ttl);
  printf("|%-20s%-20u|\n", "Protocol:", packet->protocol);
  printf("|%-20s%-20u|\n", "Checksum:", packet->checksum);
  printf("|%-20s%-20s|\n", "Source:", src);
  printf("|%-20s%-20s|\n", "Destination:", dest);
  printf("|%-40s|\n", "");

  switch(packet->protocol) {
    case ICMP:
      print_icmp(packet);
      break;
    case TCP:
      print_tcp(packet);
      break;
    case UDP:
      print_udp(packet);
      break;
    default:
      printf("|-----This protocol isn't supported------|\n\n\n\n");
  }
}

void print_icmp(const struct ipv4_packet* packet) {
  // int length = packet->total_length
  //   - (packet->ihl * 4)
  //   - 8;

  printf("|             ICMP Protocol              |\n");
  printf("|%-20s%-20u|\n", "Type:", packet->icmp.type);
  printf("|%-20s%-20u|\n", "Code:", packet->icmp.code);
  printf("|%-20s%-20u|\n", "Checksum:", packet->icmp.checksum);
  printf("|%-40s|\n", "");
  print_payload(packet->icmp.payload);
}

void print_tcp(const struct ipv4_packet* packet) {
  // int length = packet->total_length
  //   - (packet->ihl * 4)
  //   - (packet->tcp.offset * 4);

  printf("|              TCP Protocol              |\n");
  printf("|%-20s%-20u|\n", "Source Port:", packet->tcp.source_port);
  printf("|%-20s%-20u|\n", "Destination Port:", packet->tcp.destination_port);
  printf("|%-20s%-20u|\n", "Sequence:", packet->tcp.sequence);
  printf("|%-20s%-20u|\n", "Acknowledgement:", packet->tcp.acknowledgement);
  printf("|%-20s%-20u|\n", "Offset:", packet->tcp.offset);
  printf("|%-20s%-20u|\n", "Reserved:", packet->tcp.reserved);
  printf("|%-20s%-20u|\n", "Urgent Flag:", packet->tcp.urgent_flag);
  printf("|%-20s%-20u|\n", "Acknowledge Flag:", packet->tcp.acknowledge_flag);
  printf("|%-20s%-20u|\n", "Push Flag:", packet->tcp.push_flag);
  printf("|%-20s%-20u|\n", "Reset Flag:", packet->tcp.reset_flag);
  printf("|%-20s%-20u|\n", "SYN Flag:", packet->tcp.syn_flag);
  printf("|%-20s%-20u|\n", "FIN Flag:", packet->tcp.fin_flag);
  printf("|%-20s%-20u|\n", "Window Size:", packet->tcp.window_size);
  printf("|%-20s%-20u|\n", "Checksum:", packet->tcp.checksum);
  printf("|%-20s%-20u|\n", "Urgent Pointer:", packet->tcp.urgent_pointer);
  printf("|%-40s|\n", "");
  print_payload(packet->tcp.payload + (packet->tcp.offset * 4));
}

void print_udp(const struct ipv4_packet* packet) {
  // int length = packet->udp.length - 8;

  printf("|              UDP Protocol              |\n");
  printf("|%-20s%-20u|\n", "Source Port:", packet->udp.source_port);
  printf("|%-20s%-20u|\n", "Destination Port:", packet->udp.destination_port);
  printf("|%-20s%-20u|\n", "Length:", packet->udp.length);
  printf("|%-20s%-20u|\n", "Checksum:", packet->udp.checksum);
  printf("|%-40s|\n", "");
  print_payload(packet->udp.payload);
}

void print_payload(const uint8_t* payload) {
  int length = strlen((const char*) payload);

  printf("|------------------Data------------------|\n");
  for(int i = 0; i < length; i += 10) {
    for(int j = 0; j < 10; j++) {
      if(i + j < length) {
        printf("\\x%02x", payload[i + j]);
      } else {
        printf("%4s", "");
      }
    }
  }
  printf("\n\n\n\n");
  // printf("|----------------------------------------|\n\n");
}

int main(void) {
  int fd;
  int bytes;
  uint8_t buffer[BUFFER_SIZE];
  struct eth_frame* frame;
  // struct ipv4_packet* packet;

  if((fd = socket(AF_PACKET, SOCK_RAW, ntohs(ETH_P_ALL))) < 0) {
    printf("Socket failed\n");
    return -1;
  } else {
    printf("Socket passed\n");
  }

  while(1) {
    if((bytes = read(fd, buffer, BUFFER_SIZE)) > 0) {
      frame = parse_frame(buffer, bytes);
      // packet = parse_packet(frame->payload, bytes - sizeof(struct eth_frame));
      print_frame(frame);
      print_packet(&frame->packet);
      free(frame);
      // free(packet);
    }
  }


  return 0;
}
