#pragma once

#include <cstdio>
#include <string>
#include <libnet.h>
#include "ip.h"

struct flowinfo
{
    std::string protocol;
    Ip sip;
    u_int16_t sport;
    Ip dip;
    u_int16_t dport;

    bool operator<(const flowinfo& other) const;

    flowinfo Reverse();

};

struct flowinfo2
{
    int pklen;
    u_int32_t pkbytes;

    flowinfo2();
    void flowupdate(u_int32_t pkbytes);

};