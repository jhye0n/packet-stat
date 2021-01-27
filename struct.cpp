#include "struct.h"

bool flowinfo::operator<(const flowinfo& other) const{
    if(this->protocol != other.protocol) return protocol < other.protocol;
    if(this->sip != other.sip) return sip < other.sip;
    if(this->sport != other.sport) return sport < other.sport;
    if(this->dip != other.dip) return dip < other.dip;
    if(this->dport != other.dport) return dport < other.dport;
}

flowinfo flowinfo::Reverse()
{
    flowinfo reverse_flow;
    reverse_flow.sip = this->sip = dip;
    reverse_flow.sport = this->sport = dport;
    reverse_flow.dip = this->dip = sip;
    reverse_flow.dport = this->dport = sport;

    return reverse_flow;
}

flowinfo2::flowinfo2()
{
    this->pklen = 0;
    this->pkbytes = 0;
}

void flowinfo2::flowupdate(u_int32_t pkbytes)
{
    this->pklen++;
    this->pkbytes += pkbytes;
}