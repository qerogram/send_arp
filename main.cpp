#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <pcap.h>

using namespace std;
#define ARPTYPE 0x0608
#define MAC_LEN 6

struct ARP_HEADER {
    uint8_t dst_mac[MAC_LEN];
    uint8_t src_mac[MAC_LEN];
    uint16_t protocol;
    uint16_t Type_Hardware;
    uint16_t Type_Protocol;
    uint8_t LenMAC;
    uint8_t LenProtocol;
    uint16_t OPCODE;
    uint8_t lmac[MAC_LEN];
    uint8_t lhost[4];
    uint8_t rmac[MAC_LEN];
    uint8_t rhost[4];
};

int getMAC(char*, char*);
int sendPacket(pcap_t*, char*, char*, char*);

int main(int argc, char* argv[]) {
    if (argc != 4) {
        cout << "[*] Usage : send_arp [nic] [lhost] [rhost]" << endl;
        exit(1);
    }
    char *nic = argv[1], *lhost = argv[2], *rhost = argv[3], mac[MAC_LEN], errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(nic, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) exit(1);        
    inet_pton(AF_INET, lhost, lhost); inet_pton(AF_INET, rhost, rhost);
    getMAC(nic, mac);
    cout << mac << endl;
    sendPacket(handle, rhost, lhost, mac);
    pcap_close(handle);
    return 0;
}

int getMAC(char *nic, char* mac) {
    char t_mac[18] = {0}, command[512] = {0};
    int tmp, idx = 0;
    sprintf(command, "ifconfig %s | grep ether | awk '{print $2}'", nic);
    FILE* fp = popen(command, "r");
    fgets(t_mac, sizeof(t_mac), fp);
    pclose(fp);

    char *ptr = strtok(t_mac, ":");
    while(ptr != NULL) {
        tmp = strtol(ptr, NULL, 16);
        mac[idx++] = tmp;
        ptr = strtok(NULL, ":");
    }
}

int sendPacket(pcap_t* handle, char* lhost, char* rhost, char* mac) {
    struct ARP_HEADER *packet = (struct ARP_HEADER*)malloc(sizeof(struct ARP_HEADER));
    memset(packet->dst_mac, 0xff, MAC_LEN);
    memcpy(packet->src_mac, mac, MAC_LEN);
    packet->protocol = ARPTYPE;
    packet->Type_Hardware = packet->OPCODE = 0x0100;
    packet->Type_Protocol = 8;
    packet->LenMAC = MAC_LEN;
    packet->LenProtocol = 4;
    memcpy(packet->lmac, mac, MAC_LEN);
    memcpy(packet->lhost, lhost, 4);
    memset(packet->rmac, 0, MAC_LEN);
    memcpy(packet->rhost, rhost, 4);
    if (pcap_sendpacket(handle, (const u_char*)packet, 42) != 0) return -1;
    return 0;
}
