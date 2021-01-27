#include <cstdio>
#include <iostream>
#include <map>
#include <pcap.h>
#include "class.h"

using namespace std;

int main(int argc, char* argv[])
{
    if(argc < 2){
        printf("Usage : %s [pcap_file]", argv[0]);
        return 0;
    }

    char* pcap_file = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    
    pcap_t *handle = pcap_open_offline(pcap_file, errbuf);

    if(handle == nullptr){
        fprintf(stderr, "pcap_open_offline is nullptr(%s)\n", errbuf);
        return 0;
    }

    Flow Reflow = Flow();

    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;

        int res = pcap_next_ex(handle, &header, &packet);

        if(res == 0){
            continue;
        }else if(res == -1 || res == -2){
            break;
        }

        Reflow.pk_classify(header, packet);

    }

    Reflow.pk_printflow();

    pcap_close(handle);

    return 0;
}