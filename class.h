#pragma once

#include <cstdio>
#include <iostream>
#include <map>
#include <pcap.h>
#include "struct.h"

using namespace std;

typedef map<flowinfo, flowinfo2> FlowMap;

class Flow
{
    private:
        FlowMap flowtable;

        int pk_getflow(const u_char* packet, flowinfo &flow);
        void pk_updateflow(flowinfo &temp, uint32_t pklen);

    public:
        Flow();
        ~Flow();
        int pk_classify(struct pcap_pkthdr* header, const u_char* packet);
        void pk_printflow();
};