#include <cstdio>
#include <iostream>
#include "class.h"
#include "header.h"
#include "ip.h"

void Flow::pk_printflow()
{
    std::string protocol;
    int s_port, d_port;
    uint32_t pk_atob, pk_atobbyte, pk_btoa, pk_btoabyte;

    while(flowtable.size())
    {
        FlowMap::iterator it = flowtable.begin();

        flowinfo f1 = it->first;

        if(f1.protocol == "TCP")
        {
            protocol = "TCP";

        }else if(f1.protocol == "UDP")
        
        {
            protocol = "UDP";
        }

        s_port = f1.sport;
        d_port = f1.dport;
        pk_atob = flowtable[f1].pklen;
        pk_atobbyte = flowtable[f1].pkbytes;

        flowinfo f2 = f1.Reverse();

        if(flowtable.count(f2))
        {
            pk_btoa = flowtable[f2].pklen;
            pk_btoabyte = flowtable[f2].pkbytes;
        }

        else{
            pk_btoa = 0;
            pk_btoabyte = 0;
        }

        printf("%12s", protocol.c_str());

    }
}

int Flow::pk_getflow(const u_char* packet, flowinfo &flow)
{
    eth_hdr = (struct ethernet_hdr *) packet;

    if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP)
    {
        iphdr = (struct ip *) (packet + sizeof(ethernet_hdr));

        flow.sip = Ip(ntohl(iphdr->ip_src.s_addr));
        flow.dip = Ip(ntohl(iphdr->ip_dst.s_addr));

        if(iphdr->ip_p == IPPROTO_TCP)
        {
            tcp_hdr = (struct tcphdr *) (packet + sizeof(ethernet_hdr) + sizeof(ip));

            flow.sport = ntohs(tcp_hdr->th_sport);
            flow.dport = ntohs(tcp_hdr->th_dport);
        }

        if(iphdr->ip_p == IPPROTO_UDP)
        {
            udp_hdr = (struct udphdr *) (packet + sizeof(ethernet_hdr) + sizeof(tcphdr));

            flow.sport = ntohs(udp_hdr->uh_sport);
            flow.dport = ntohs(udp_hdr->uh_dport);
        }
    }
}

void Flow::pk_updateflow(flowinfo &flow, uint32_t pklen)
{
    if(!flowtable.count(flow))
    {
        flowinfo2 newflow = flowinfo2();
        flowtable.insert(std::make_pair(flow, newflow));
    }

    flowtable[flow].flowupdate(pklen);
}

int Flow::pk_classify(struct pcap_pkthdr* header, const u_char* packet)
{
    flowinfo flow;

    pk_getflow(packet, flow);

    pk_updateflow(flow, header->caplen);
}