#pragma once

#include <cstdio>
#include <libnet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define ETHER_ADDR_LEN 6

struct ethernet_hdr *eth_hdr;
struct ethernet_hdr
{
    u_int8_t ether_dhost[ETHER_ADDR_LEN];
    u_int8_t ether_shost[ETHER_ADDR_LEN];
    u_int16_t ether_type;
};

struct ip *iphdr;
struct tcphdr *tcp_hdr;
struct udphdr *udp_hdr;