#ifndef _NET_H_
#define _NET_H_

#include "types.h"

// ethernet
#define ETHER_ADDR_LEN 6        // length of a mac address
#define ETHER_TYPE_IP 0x800     // IPV4
#define ETHER_TYPE_IPV6 0x86DD  // IPV6
#define ETHER_TYPE_ARP 0x806    // ARP

// ip protocol
#define IPv4 4
#define IPv6 6

// default header values
#define IPv4_Default_TOS 0
#define IPv4_Default_ID 0
#define IPv4_Default_TTL 64
#define IPv4_Default_PROTO 6 /*tcp*/

// protocol
#define IPPROTO_ICMP 1
#define IPPROTO_IGMP 2
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_IGRP 88
#define IPPROTO_OSRF 89

// tcp signal
#define TCP_SIGNAL_FIN 0b00000001
#define TCP_SIGNAL_SYN 0b00000010
#define TCP_SIGNAL_RST 0b00000100
#define TCP_SIGNAL_PSH 0b00001000
#define TCP_SIGNAL_ACK 0b00010000
#define TCP_SIGNAL_URG 0b00100000

//
#define MAX_BUFFER 1024
#define IP_BUF_LEN 50



#endif