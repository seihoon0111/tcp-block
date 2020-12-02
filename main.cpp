#include <cstdio>
#include <pcap.h>
#include <libnet.h>
#include <string.h>
uint8_t forward[1000]={0,};
uint8_t backward[1000]={0,};

void usage() {
    printf("syntax : tcp-block <interface> <pattern>\n");
    printf("sample : tcp-block wlan0 test.gilgil.net\n");
}

pcap_t* handle;
uint8_t mymac[6];
const char* block="blocked!!!";

typedef struct tcp_packet
{
    struct libnet_ethernet_hdr eth_hdr;
    struct libnet_ipv4_hdr ip_hdr;
    struct libnet_tcp_hdr tcp_hdr;
}tcp_packet;


int RSTForward(uint8_t* packet,unsigned int length){
 
    struct libnet_ethernet_hdr* eth_hdr=(struct libnet_ethernet_hdr *)packet;
    struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr *)(packet +LIBNET_ETH_H);
    struct libnet_tcp_hdr* tcp_hdr=(struct libnet_tcp_hdr *)(packet+LIBNET_ETH_H+ip_hdr->ip_hl*4);

    for(int i=0;i<6;i++){
     eth_hdr->ether_shost[i]=mymac[i];
    }
    ip_hdr->ip_len=htons(ip_hdr->ip_hl*4+tcp_hdr->th_off*4);
    tcp_hdr->th_seq=htonl(ntohl(tcp_hdr->th_seq)+tcp_hdr->th_off*4);
    tcp_hdr->th_flags|=TH_RST;

    uint32_t checksum=0;  
    ip_hdr->ip_sum =0;
    uint16_t* ip_h=(uint16_t*)ip_hdr;
    for(int i=0;i<(ip_hdr->ip_hl*4)/2;i++){
        checksum+=ip_h[i];
    }
    checksum=(checksum>>16)+(checksum&0xffff);
    checksum=(checksum>>16)+(checksum&0xffff);
    checksum= ~checksum;
    ip_hdr->ip_sum =(u_int16_t)checksum;   

    checksum=0;
    tcp_hdr->th_sum =0;
    uint16_t* tcp_h=(uint16_t*)tcp_hdr;
    for(int i=0;i<(tcp_hdr->th_off*4)/2;i++){
        checksum+=tcp_h[i];
    }
    checksum+=(ip_hdr->ip_src.s_addr>>16)+(ip_hdr->ip_src.s_addr&0xffff);
    checksum+=(ip_hdr->ip_dst.s_addr>>16)+(ip_hdr->ip_dst.s_addr&0xffff);
    checksum+=ip_hdr->ip_p;
    checksum+=tcp_hdr->th_off*4;
    checksum=(checksum>>16)+(checksum&0xffff);
    checksum=(checksum>>16)+(checksum&0xffff);
    checksum= ~checksum;
    tcp_hdr->th_sum =(u_int16_t)checksum;   

    int len=  LIBNET_ETH_H+ip_hdr->ip_hl*4+tcp_hdr->th_off*4;
    
	int res1 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), len);
	if (res1 != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res1, pcap_geterr(handle));
	}
    printf("send rst\n");
    return 0;
}

int FINBackward(uint8_t* packet,unsigned int length){
 
    struct libnet_ethernet_hdr* eth_hdr=(struct libnet_ethernet_hdr *)packet;
    struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr *)(packet +LIBNET_ETH_H);
    struct libnet_tcp_hdr* tcp_hdr=(struct libnet_tcp_hdr *)(packet+LIBNET_ETH_H+ip_hdr->ip_hl*4);
    strncpy((char*)tcp_hdr+tcp_hdr->th_off*4,block,11);

    for(int i=0;i<6;i++){
     eth_hdr->ether_dhost[i]=eth_hdr->ether_shost[i];
    }
    for(int i=0;i<6;i++){
     eth_hdr->ether_shost[i]=mymac[i];
    }

    ip_hdr->ip_len=htons(ip_hdr->ip_hl*4+tcp_hdr->th_off*4+11);
    ip_hdr->ip_ttl=0x80;
    uint32_t src_ip=ip_hdr->ip_src.s_addr;
    uint32_t dst_ip=ip_hdr->ip_dst.s_addr;
    ip_hdr->ip_dst.s_addr=src_ip;
    ip_hdr->ip_src.s_addr=dst_ip;

    uint16_t dport=tcp_hdr->th_dport;
    uint16_t sport=tcp_hdr->th_sport; 
    tcp_hdr->th_sport=dport;
    tcp_hdr->th_dport=sport;   
    tcp_hdr->th_seq=tcp_hdr->th_ack;
    tcp_hdr->th_ack=htonl(ntohl(tcp_hdr->th_seq)+tcp_hdr->th_off*4);
    tcp_hdr->th_flags|=TH_FIN;

    uint32_t checksum=0;  
    ip_hdr->ip_sum =0;
    uint16_t* ip_h=(uint16_t*)ip_hdr;
    for(int i=0;i<(ip_hdr->ip_hl*4)/2;i++){
        checksum+=ip_h[i];
    }
    checksum=(checksum>>16)+(checksum&0xffff);
    checksum=(checksum>>16)+(checksum&0xffff);
    checksum= ~checksum;
    ip_hdr->ip_sum =(u_int16_t)checksum;   

    checksum=0;
    tcp_hdr->th_sum =0;
    uint16_t* tcp_h=(uint16_t*)tcp_hdr;
    for(int i=0;i<(tcp_hdr->th_off*4+12)/2;i++){
        checksum+=tcp_h[i];
    }
    checksum+=(ip_hdr->ip_src.s_addr>>16)+(ip_hdr->ip_src.s_addr&0xffff);
    checksum+=(ip_hdr->ip_dst.s_addr>>16)+(ip_hdr->ip_dst.s_addr&0xffff);
    checksum+=ip_hdr->ip_p;
    checksum+=tcp_hdr->th_off*4;
    checksum=(checksum>>16)+(checksum&0xffff);
    checksum=(checksum>>16)+(checksum&0xffff);
    checksum= ~checksum;
    tcp_hdr->th_sum =(u_int16_t)checksum;   

    int len=  LIBNET_ETH_H+ip_hdr->ip_hl*4+tcp_hdr->th_off*4+8;
    for(int i=0;i<500;i++){
                  printf("%02x ",forward[i]);
    }
    
	int res1 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&forward), len);
	if (res1 != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res1, pcap_geterr(handle));
	}
    printf("send fin\n");
    return 0;
}

int find_pattern(const u_char* packet, unsigned int length, char* pattern){	
    struct libnet_ethernet_hdr* eth_hdr=(struct libnet_ethernet_hdr *)packet;
    if(length<LIBNET_ETH_H){
        return 0;
    }
	struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr *)(packet +LIBNET_ETH_H);
    if(ip_hdr->ip_p != 0x06){
        return 0;
    }
    if(length<LIBNET_ETH_H+ip_hdr->ip_hl*4){
        return 0;
    }
	struct libnet_tcp_hdr* tcp_hdr=(struct libnet_tcp_hdr *)(packet+LIBNET_ETH_H+ip_hdr->ip_hl*4);
    uint8_t* data=(uint8_t*)tcp_hdr+tcp_hdr->th_off*4;
    int data_len=ntohs(ip_hdr->ip_len) - ip_hdr->ip_hl*4 - tcp_hdr->th_off*4;
    if(data_len<strlen(pattern)){
        return 0;
    }
    for(int i=0;i<data_len-strlen(pattern);i++){
        if(!strncmp((char*)data+i,pattern,strlen(pattern)))
            {
                printf("find it\n");

                memcpy(forward,packet,1000);
                RSTForward(forward,length);
                for(int i=0;i<500;i++){
                  printf("%02x ",forward[i]);

                }
                memcpy(backward,packet,1000);
                FINBackward(backward,length);

                break;
            }
    }
    return 0;
}


int main(int argc, char*argv[]){
        if (argc != 3) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char* pattern= argv[2];
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

	struct ifreq ifrq;
	int soc = socket(AF_INET, SOCK_DGRAM, 0);
	strcpy(ifrq.ifr_name, dev);
	ioctl(soc,SIOCGIFHWADDR, &ifrq);
	for (int i=0; i<6; i++){
		mymac[i] = ifrq.ifr_hwaddr.sa_data[i];
    }



    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        find_pattern(packet, header->len,pattern);
    }

    pcap_close(handle);
}