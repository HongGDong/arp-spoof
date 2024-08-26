#include <pcap.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <map>
#include <cstring>
#include <iostream>

std::map<std::string, std::string> IP_GATE; // IP, 게이트웨이에 대한 맵
std::map<Ip, Mac> TABLE2; // IP, MAC 주소의 매핑을 저장하는 맵

#pragma pack(push, 1)
struct EthArpPacket final 
{
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

char errbuf[PCAP_ERRBUF_SIZE];
unsigned char MY_MAC[6];
char MY_IP[INET_ADDRSTRLEN];

struct ipheader {
    unsigned char      iph_ihl : 4;
    unsigned char      iph_ver : 4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flag : 3;
    unsigned short int iph_offset : 13;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    struct  in_addr    iph_sourceip;
    struct  in_addr    iph_destip;
};

int get_ip(const char* ifname, char* ip) // 인터페이스의 IP를 가져옴
{
    struct ifaddrs* ifaddr, * ifa;

    if (getifaddrs(&ifaddr) == -1) { // 모든 인터페이스의 IP 주소를 가져옴
        perror("getifaddrs");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) // 목록을 순환
    {
        if (ifa->ifa_addr == NULL) continue;

        // 입력한 인터페이스를 찾았다면
        if (strncmp(ifa->ifa_name, ifname, IFNAMSIZ) == 0) {
            if (ifa->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in* sa = (struct sockaddr_in*)ifa->ifa_addr;
                inet_ntop(AF_INET, &(sa->sin_addr), ip, INET_ADDRSTRLEN);
                freeifaddrs(ifaddr);
                return 0;
            }
        }
    }
    freeifaddrs(ifaddr);
    return -1;
}

int get_mac(const char* ifname, unsigned char* mac) { // 인터페이스의 MAC 주소를 가져옴
    struct ifaddrs* ifaddr, * ifa;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (strncmp(ifa->ifa_name, ifname, IFNAMSIZ) == 0) {
            int sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (sock == -1) {
                perror("socket");
                freeifaddrs(ifaddr);
                return -1;
            }

            struct ifreq ifr;
            strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ - 1);
            ifr.ifr_name[IFNAMSIZ - 1] = '\0';

            // loctl로 MAC 주소를 가져옴
            if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                memcpy(mac, ifr.ifr_hwaddr.sa_data, 6); // MAC 주소를 메모리에 복사
                close(sock);
                freeifaddrs(ifaddr);
                return 0;
            }
            else {
                perror("ioctl");
                close(sock);
            }
        }
    }

    freeifaddrs(ifaddr);
    return -1;
}

// ARP 패킷 전송
int arp_packet(const char* ifname, Ip sender_addr, Ip target_addr, Mac sender_mac) {
    pcap_t* handle = pcap_open_live(ifname, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) failed: %s\n", ifname, errbuf);
        return -1;
    }

    EthArpPacket packet;
    packet.eth_.dmac_ = sender_mac;
    packet.eth_.smac_ = Mac(MY_MAC);
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(MY_MAC);
    packet.arp_.sip_ = htonl(target_addr);
    packet.arp_.tmac_ = sender_mac;
    packet.arp_.tip_ = htonl(sender_addr);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket failed: %s\n", pcap_geterr(handle));
    }
    pcap_close(handle);
    return 0;
}

// 릴레이 함수
int relay_packet(const u_char* packet, const char* ifname, const char* s_addr, const char* d_addr) {
    pcap_t* handle = pcap_open_live(ifname, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) failed: %s\n", ifname, errbuf);
        return -1;
    }

    struct EthHdr* eth = (struct EthHdr*)packet;
    struct ipheader* ip_header = (struct ipheader*)(packet + sizeof(struct EthHdr));
    eth->smac_ = Mac(MY_MAC);

    // dest MAC 주소를 조회
    auto it = TABLE2.find(Ip(d_addr));
    if (it != TABLE2.end()) {
        Mac destmac = it->second;
        auto gate_it = IP_GATE.find(s_addr); // 게이트웨이 IP 탐색
        if (gate_it != IP_GATE.end()) {
            std::string gate_ip = gate_it->second;
            auto gate_mac_it = TABLE2.find(Ip(gate_ip));
            if (gate_mac_it != TABLE2.end()) {
                Mac gate_mac = gate_mac_it->second; // 게이트웨이 MAC 탐색
                eth->dmac_ = gate_mac;
            }
        }
    }
    else {
        eth->dmac_ = it->second; // MAC 주소 못찾으면
    }

    int packet_len = sizeof(struct EthHdr) + ntohs(ip_header->iph_len);

    int res = pcap_sendpacket(handle, packet, packet_len);
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket failed: %s\n", pcap_geterr(handle));
    }
    pcap_close(handle);
    return 0;
}

// ARP 초기화
int arp_init(const char* ifname, const char* sender_addr, const char* target_addr) {
    pcap_t* pcap = pcap_open_live(ifname, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) failed: %s\n", ifname, errbuf);
        return -1;
    }

    EthArpPacket packet;
    get_mac(ifname, MY_MAC);
    get_ip(ifname, MY_IP);
    Mac sender_mac;

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = Mac(MY_MAC);
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(MY_MAC);
    packet.arp_.sip_ = htonl(Ip(MY_IP));
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(Ip(sender_addr));

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket failed: %s\n", pcap_geterr(pcap));
    }

    struct pcap_pkthdr* header;
    const u_char* recv_packet;
    while (true) {
        int ret = pcap_next_ex(pcap, &header, &recv_packet);
        if (ret == 0) continue;
        if (ret == PCAP_ERROR || ret == PCAP_ERROR_BREAK) {
            fprintf(stderr, "pcap_next_ex returned %d: %s\n", ret, pcap_geterr(pcap));
            break;
        }

        struct EthHdr* eth = (struct EthHdr*)recv_packet;
        if (eth->type() == 0x0806) { // ARP 패킷
            sender_mac = eth->smac(); // MAC 주소 추출
            TABLE2.insert({ Ip(sender_addr), sender_mac });
            break;
        }
    }
    pcap_close(pcap);

    pcap_t* handle = pcap_open_live(ifname, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) failed: %s\n", ifname, errbuf);
        return -1;
    }

    EthArpPacket packet1;
    packet1.eth_.dmac_ = sender_mac;
    packet1.eth_.smac_ = Mac(MY_MAC);
    packet1.eth_.type_ = htons(EthHdr::Arp);
    packet1.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet1.arp_.pro_ = htons(EthHdr::Ip4);
    packet1.arp_.hln_ = Mac::SIZE;
    packet1.arp_.pln_ = Ip::SIZE;
    packet1.arp_.op_ = htons(ArpHdr::Request);
    packet1.arp_.smac_ = Mac(MY_MAC);
    packet1.arp_.sip_ = htonl(Ip(target_addr));
    packet1.arp_.tmac_ = sender_mac;
    packet1.arp_.tip_ = htonl(Ip(sender_addr));

    int res1 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet1), sizeof(EthArpPacket));
    if (res1 != 0) {
        fprintf(stderr, "pcap_sendpacket failed: %s\n", pcap_geterr(handle));
    }
    pcap_close(handle);
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 3 || (argc - 2) % 2 != 0) {
        fprintf(stderr, "Usage: %s <interface> <sender1> <target1> [<sender2> <target2> ...]\n", argv[0]);
        return -1;
    }

    char ifname[100];
    strcpy(ifname, argv[1]);
    get_mac(ifname, MY_MAC);
    get_ip(ifname, MY_IP);

    char sender[100][100];
    char target[100][100];
    int s_index = 0;
    int t_index = 0;

    for (int i = 2; i < argc; i++) {
        if (i % 2 == 0) {
            strncpy(sender[s_index], argv[i], 99);
            sender[s_index][99] = '\0';
            s_index++;
        }
        else {
            strncpy(target[t_index], argv[i], 99);
            target[t_index][99] = '\0';
            t_index++;
        }
    }

    // ARP 초기화
    for (int i = 0; i < s_index; i++) {
        IP_GATE.insert({ sender[i], target[i] }); // IP <-> 게이트웨이 매핑
        if (arp_init(ifname, sender[i], target[i]) != 0) {
            fprintf(stderr, "ARP init failed for %s -> %s\n", sender[i], target[i]);
            return -1;
        }
        if (arp_init(ifname, target[i], sender[i]) != 0) {
            fprintf(stderr, "ARP init failed for %s -> %s\n", target[i], sender[i]);
            return -1;
        }
    }

    pcap_t* pcap = pcap_open_live(ifname, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) failed: %s\n", ifname, errbuf);
        return -1;
    }

    printf("Starting capture loop...\n");

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            fprintf(stderr, "pcap_next_ex returned %d: %s\n", res, pcap_geterr(pcap));
            break;
        }

        struct EthHdr* eth = (struct EthHdr*)packet;
        if (eth->type() == 0x0806) { // ARP 패킷
            printf("ARP packet received.\n");
            struct ArpHdr* arp_header = (struct ArpHdr*)(packet + sizeof(struct EthHdr));
            Ip sender_ip(ntohl(arp_header->sip_));
            Ip target_ip(ntohl(arp_header->tip_));
            arp_packet(ifname, sender_ip, target_ip, eth->smac_);
        }
        else if (eth->type() == 0x0800) { // IP 패킷
            printf("IP packet received.\n");
            struct ipheader* ip_header = (struct ipheader*)(packet + sizeof(struct EthHdr));
            char sender_addr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip_header->iph_sourceip), sender_addr, INET_ADDRSTRLEN);
            char target_addr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip_header->iph_destip), target_addr, INET_ADDRSTRLEN);
            relay_packet(packet, ifname, sender_addr, target_addr);
        }
    }
    pcap_close(pcap);
    return 0;
}