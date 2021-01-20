#ifndef NETWORK_H
#define NETWORK_H

struct __attribute__((__packed__)) icmp {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint8_t payload[];
};

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
struct __attribute__((__packed__)) tcp {
  uint16_t source_port;
  uint16_t destination_port;
  uint32_t sequence;
  uint32_t acknowledgement;
  uint16_t acknowledge_flag: 1;
  uint16_t urgent_flag: 1;
  uint16_t reserved: 6;
  uint16_t offset: 4;
  uint16_t push_flag;
  uint16_t fin_flag: 1;
  uint16_t syn_flag: 1;
  uint16_t reset_flag: 1;
  uint16_t window_size;
  uint16_t checksum;
  uint16_t urgent_pointer;
  uint8_t payload[];
};
#else
struct __attribute__((__packed__)) tcp {
  uint16_t source_port;
  uint16_t destination_port;
  uint32_t sequence;
  uint32_t acknowledgement;
  uint16_t offset: 4;
  uint16_t reserved: 6;
  uint16_t urgent_flag: 1;
  uint16_t acknowledge_flag: 1;
  uint16_t push_flag;
  uint16_t reset_flag: 1;
  uint16_t syn_flag: 1;
  uint16_t fin_flag: 1;
  uint16_t window_size;
  uint16_t checksum;
  uint16_t urgent_pointer;
  uint8_t payload[];
};
#endif

struct __attribute__((__packed__)) udp {
  uint16_t source_port;
  uint16_t destination_port;
  uint16_t length;
  uint16_t checksum;
  uint8_t payload[];
};

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
struct __attribute__((__packed__)) ipv4_packet {
  uint8_t ihl: 4;
  uint8_t version: 4;
  uint8_t service;
  uint16_t total_length;
  uint16_t identification;
  uint16_t fragment_offset: 13;
  uint16_t mf: 1;
  uint16_t df: 1;
  uint16_t zero: 1;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t checksum;
  uint8_t source[4];
  uint8_t destination[4];
  union {
    struct icmp icmp;
    struct tcp tcp;
    struct udp udp;
  };
};
#else
struct __attribute__((__packed__)) ipv4_packet{
  uint8_t version: 4;
  uint8_t ihl: 4;
  uint8_t service;
  uint16_t total_length;
  uint16_t identification;
  uint16_t zero: 1;
  uint16_t df: 1;
  uint16_t mf: 1;
  uint16_t fragment_offset: 13;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t checksum;
  uint8_t source[4];
  uint8_t destination[4];
  union {
    struct icmp icmp;
    struct tcp tcp;
    struct udp udp;
  };
};
#endif

struct __attribute__((__packed__)) eth_frame {
  uint8_t destination[6];
  uint8_t source[6];
  uint16_t ethertype;
  struct ipv4_packet packet;
};

#endif
