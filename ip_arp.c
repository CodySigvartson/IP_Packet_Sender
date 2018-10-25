/********************************
Programmer	Last Modified		Description
---------	-------------		---------------
Cody Sigvartson	10_24_18			Initial development

Program description:
This program builds and sends ip packets to both local networks
and through a router interface to different subnets. This program
was built on top of my ethernet packet sender/receiver program.
********************************/

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip.h>

#define BUF_SIZ		65535
#define SEND 0
#define RECV 1

#define ARPHDRSIZ 28
#define ETHHDRSIZ 14
#define IPHDRSIZ 20

unsigned long get_ip_saddr(char *if_name, int sockfd);
unsigned long get_netmask(char *if_name, int sockfd);
uint16_t ip_checksum(void *vdata, size_t length);
struct arp_hdr constructArpRequest(char if_name[], int sockfd, struct in_addr dst, struct ifreq if_hwaddr);
struct iphdr constructIpHeader(struct in_addr dst, struct in_addr router, char if_name[], int sockfd, int sizePayload);
void recv_message(char if_name[], struct sockaddr_ll sk_addr, int sockfd);
void send_message(char if_name[], struct sockaddr_ll sk_addr, char hw_addr[], char payload[], int sockfd, int type, struct ifreq if_hwaddr, int sizePayload);

typedef struct arp_hdr{
	uint16_t ar_hrd;
	uint16_t ar_pro;
	uint8_t ar_hln;
	uint8_t ar_pln;
	uint16_t ar_op;
	uint8_t ar_sha[6];
	uint8_t ar_sip[4];
	uint8_t ar_tha[6];
	uint8_t ar_tip[4];
}arp_hdr;

void send_message(char if_name[], struct sockaddr_ll sk_addr, char hw_addr[], char payload[], int sockfd, int type, struct ifreq if_hwaddr, int sizePayload){
	// build ethernet frame
	struct ether_header frame;
	memset(&frame,0,sizeof(struct ether_header));
	memcpy(frame.ether_dhost, hw_addr, 6);
	memcpy(frame.ether_shost, if_hwaddr.ifr_hwaddr.sa_data, 6);
	switch(type){
		case 1: // IP
			frame.ether_type = htons(ETH_P_IP);
			break;
		case 2: // ARP
			frame.ether_type = htons(ETHERTYPE_ARP);
			break;
		default:
			frame.ether_type = htons(ETH_P_IP);
			break;

	}

	struct ifreq if_idx;
	memset(&if_idx,0,sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, if_name, IFNAMSIZ-1);
	if(ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0){
		perror("SIOCGIFINDEX");
	}

	// pack frame header
	unsigned char buff[BUF_SIZ];
	char *eth_header = (char *)&frame;
	memcpy(buff,eth_header,ETHHDRSIZ);
	memcpy(&buff[ETHHDRSIZ],payload,sizePayload);

	sk_addr.sll_ifindex = if_idx.ifr_ifindex;
	sk_addr.sll_halen = ETH_ALEN;
	printf("size payload: %d\n",sizePayload);
	int byteSent = sendto(sockfd, buff, ETHHDRSIZ+sizePayload, 0, (struct sockaddr*)&sk_addr, sizeof(struct sockaddr_ll));
	printf("%d bytes sent!\n", byteSent);
}

void recv_message(char if_name[], struct sockaddr_ll sk_addr, int sockfd){
	struct ifreq if_idx;
	memset(&if_idx,0,sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, if_name, IFNAMSIZ-1);
	if(ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0){
		perror("SIOCGIFINDEX");
	}

	if(ioctl(sockfd, SIOCGIFHWADDR, &if_idx) < 0){
		perror("SIOCGIFINDEX");
	}

	unsigned char buff[BUF_SIZ];
	int sk_addr_size = sizeof(struct sockaddr_ll);
	printf("Receiving...\n");
	int recvLen = recvfrom(sockfd, buff, BUF_SIZ, 0 , (struct sockaddr*)&sk_addr, &sk_addr_size);
	
	printf("%d bytes received!\n", recvLen);

	unsigned char src_mac[6];
	memcpy(src_mac, &buff[6], 6);
	
	unsigned char payload[BUF_SIZ];
	memcpy(payload, &buff[14], BUF_SIZ-sizeof(struct ether_header));

	printf("Message: %s\n",payload);
	printf("Source MAC: [%X][%X][%X][%X][%X][%X]\n",src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]);
}

struct iphdr constructIpHeader(struct in_addr dst, struct in_addr router, char if_name[], int sockfd, int sizePayload){
	printf("constructing IP header...\n");
	struct iphdr ip_hdr;
	ip_hdr.ihl = 5;
	ip_hdr.version = 4;
	ip_hdr.tos = 0;
	ip_hdr.tot_len = htons(IPHDRSIZ+sizePayload);
	ip_hdr.id = 4;
	ip_hdr.frag_off = 0x0;
	ip_hdr.ttl = 0x40;
	ip_hdr.protocol = 6;
	ip_hdr.check = 0;
	ip_hdr.saddr = get_ip_saddr(if_name,sockfd);
	ip_hdr.daddr = dst.s_addr;

	ip_hdr.check = ip_checksum(&ip_hdr, IPHDRSIZ);
	printf("IP header constructed...\n");
	return ip_hdr; 
}

struct arp_hdr constructArpRequest(char if_name[], int sockfd, struct in_addr dst, struct ifreq if_hwaddr){
	printf("constructing ARP request...\n");
	struct arp_hdr arphdr;
	arphdr.ar_hrd = htons(0x0001);
	arphdr.ar_pro = htons(0x0800); 
	arphdr.ar_hln = 6;
	arphdr.ar_pln = 4;
	arphdr.ar_op = htons(0x0001);

	memcpy(arphdr.ar_sha, if_hwaddr.ifr_hwaddr.sa_data, 6);
	unsigned long sip = get_ip_saddr(if_name,sockfd);
	printf("source IP address: %lu\n", sip);
	memcpy(arphdr.ar_sip, &sip, 4);
	memset(arphdr.ar_tha, 0, 6);
	memcpy(arphdr.ar_tip, &dst.s_addr, 4);
	printf("ARP request has been constructed:\n");
//	printf("source ip: %02X.%02X.%02X.%02X\n",arphdr.ar_sip[0],arphdr.ar_sip[1],arphdr.ar_sip[2],arphdr.ar_sip[3]);
//	printf("target ip: %02X.%02X.%02X.%02X\n",arphdr.ar_tip[0],arphdr.ar_tip[1],arphdr.ar_tip[2],arphdr.ar_tip[3]);
//	printf("target ha: [%02X]:[%02X]:[%02X]:[%02X]:[%02X]:[%02X]\n",arphdr.ar_tha[0],arphdr.ar_tha[1],arphdr.ar_tha[2],arphdr.ar_tha[3], arphdr.ar_tha[4], arphdr.ar_tha[5]);
//	printf("source ha: [%02X]:[%02X]:[%02X]:[%02X]:[%02X]:[%02X]\n",arphdr.ar_sha[0],arphdr.ar_sha[1],arphdr.ar_sha[2],arphdr.ar_sha[3], arphdr.ar_sha[4], arphdr.ar_sha[5]);
	return arphdr;
}


// ip_checksum provided by Adam Hahn
uint16_t ip_checksum(void *vdata, size_t length){
	printf("calculating checksum...\n");
	char *data=(char *)vdata;
	uint32_t acc=0xffff;
	
	for(size_t i = 0; i+1<length; i+=2){
		uint16_t word;
		memcpy(&word,data+i,2);
		acc += ntohs(word);
		if(acc > 0xffff){
			acc -= 0xffff;
		}
	}
	if(length & 1){
		uint16_t word = 0;
		memcpy(&word,data+length-1,1);
		acc += ntohs(word);
		if(acc > 0xffff){
			acc -= 0xffff;
		}
	}
	printf("checksum calculated.\n");
	return htons(~acc);
}

unsigned long get_netmask(char *if_name, int sockfd){
	struct ifreq if_idx;
	memset(&if_idx,0,sizeof(struct ifreq));
	strncpy(if_idx.ifr_name,if_name,IFNAMSIZ-1);
	if((ioctl(sockfd,SIOCGIFNETMASK,&if_idx)) == -1)
		perror("ioctl():");
	return ((struct sockaddr_in *)&if_idx.ifr_netmask)->sin_addr.s_addr;
}

unsigned long get_ip_saddr(char *if_name, int sockfd){
	printf("retrieving source IP...\n");
	struct ifreq if_idx;
	memset(&if_idx,0,sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, if_name, IFNAMSIZ-1);
	if(ioctl(sockfd, SIOCGIFADDR, &if_idx) < 0)
		perror("SIOCGIFADDR");
	printf("source IP obtained.\n");
	return ((struct sockaddr_in *)&if_idx.ifr_addr)->sin_addr.s_addr;
}

int main(int argc, char *argv[])
{
	int mode;
	char buff[BUF_SIZ];
	char broadcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
	char interfaceName[IFNAMSIZ];
	memset(buff, 0, BUF_SIZ);
	struct in_addr dst_ip;
	struct in_addr router_ip;
	
	int correct=0;
	if (argc > 1){
		if(strncmp(argv[1],"Send", 4)==0){
			if (argc == 6){
				mode=SEND; 
				inet_aton(argv[3], &dst_ip);
				inet_aton(argv[4], &router_ip);
				strncpy(buff, argv[5], BUF_SIZ);
				printf("Sending payload: %s\n", buff);
				correct=1;
			}
		}
		else if(strncmp(argv[1],"Recv", 4)==0){
			if (argc == 3){
				mode=RECV;
				correct=1;
			}
		}
		strncpy(interfaceName, argv[2], IFNAMSIZ);
		printf("interface: %s\n",interfaceName);
	 }
	 if(!correct){
		fprintf(stderr, "./455_proj2 Send <InterfaceName>  <DestIP> <RouterIP> <Message>\n");
		fprintf(stderr, "./455_proj2 Recv <InterfaceName>\n");
		exit(1);
	 }

	struct sockaddr_ll sk_addr;
	memset(&sk_addr, 0, sizeof(struct sockaddr_ll));


	if(mode == SEND){
		// create socket
		int sockfd = -1;
		if((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))<0){
			perror("socket() failed!");
		}

		// connect to interface name
		struct ifreq if_hwaddr;
		memset(&if_hwaddr,0,sizeof(struct ifreq));
		strncpy(if_hwaddr.ifr_name, interfaceName, IFNAMSIZ-1);
		if(ioctl(sockfd, SIOCGIFHWADDR, &if_hwaddr) < 0){
			perror("SIOCGIFHWADDR");
		}

		// if netmask is different, send ARP request for my router IP first
		// once I have MAC of my router, send  dst MAC router, dest IP

		// send ARP request
		struct arp_hdr arpRequest = constructArpRequest(interfaceName, sockfd, router_ip, if_hwaddr);
		char payload[ARPHDRSIZ+strlen(buff)+1];
		char *arp = (char *)&arpRequest;
		memcpy(payload,arp,ARPHDRSIZ);
		memcpy(&payload[ARPHDRSIZ],buff,strlen(buff));
		send_message(interfaceName, sk_addr, broadcast, payload, sockfd, 2, if_hwaddr, ARPHDRSIZ+strlen(buff));

		// wait for ARP response
		unsigned char response[BUF_SIZ];
		char dst_mac[6];
		int arpReceived = 0;
		int sk_addr_size = sizeof(struct sockaddr_ll);
		while(!arpReceived){
			memset(&sk_addr, 0, sk_addr_size);
			int recvLen = recvfrom(sockfd, response, BUF_SIZ, 0 , (struct sockaddr*)&sk_addr, &sk_addr_size);
			if(response[12] == 0x08 && response[13] == 0x06 && response[20] == 0x00 && response[21] == 0x02){
				printf("ARP reply received!\n");
				memcpy(dst_mac,&response[22],6);
				printf("Dest MAC: [%02X][%02X][%02X][%02X][%02X][%02X]\n",dst_mac[0],dst_mac[1],dst_mac[2],dst_mac[3],dst_mac[4],dst_mac[5]);
				arpReceived = 1;
			}
		}

		// send IP packet
		memset(&sk_addr,0,sk_addr_size);
		struct iphdr ip_hdr= constructIpHeader(dst_ip, dst_ip, interfaceName, sockfd, strlen(buff));
		char ip_payload[IPHDRSIZ+strlen(buff)+1];
		char *ip = (char *)&ip_hdr;
		memcpy(ip_payload, ip, IPHDRSIZ);
		memcpy(&ip_payload[IPHDRSIZ], buff, strlen(buff));
		send_message(interfaceName, sk_addr, dst_mac, ip_payload, sockfd, 1, if_hwaddr, IPHDRSIZ+strlen(buff));
	}
	else if (mode == RECV){
		int sockfd = -1;
		if((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))<0){
			perror("socket() failed!");
		}
		// wait for ARP request
		unsigned char request[BUF_SIZ];
		char target[4];
		int arpReceived = 0;
		int sk_addr_size = sizeof(struct sockaddr_ll);
		while(!arpReceived){
			memset(&sk_addr, 0, sk_addr_size);
			int recvLen = recvfrom(sockfd, request, BUF_SIZ, 0 , (struct sockaddr*)&sk_addr, &sk_addr_size);
			if(request[12] == 0x08 && request[13] == 0x06 && request[20] == 0x00 && request[21] == 0x01){
				printf("ARP request received!\n");
				memcpy(target,&request[38],4);
				printf("Seeing if target IP: %02X.%02X.%02X.%02X is me...\n",target[0],target[1],target[2],target[3]);
				unsigned long myip_addr = get_ip_saddr(interfaceName, sockfd);
				char myip[4];
				memcpy(myip, &myip_addr, 4);
				if(strncmp(myip,target,4)==0){
					printf("I am who you're looking for!\n");
					arpReceived = 1;
				}
				
			}
		}
	}

	return 0;
}
