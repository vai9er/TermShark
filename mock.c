#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/ethernet.h>
#include <net/if.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <netinet/ip.h>       // IP header
#include <netinet/ip_icmp.h>  // ICMP header
#include <netinet/udp.h>      // UDP header
#include <netinet/tcp.h>      // TCP header


typedef enum {
    PROTOCOL_ICMP = 1,
    PROTOCOL_IGMP = 2,
    PROTOCOL_TCP  = 6,
    PROTOCOL_UDP  = 17,
    PROTOCOL_OTHER
} ProtocolType;

typedef struct {
    struct timeval timestamp;
    int packet_no;
    ProtocolType protocol;
    char src_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    int size;
} PacketInfo;

void print_packet_summary(const PacketInfo *pkt_info, const struct timeval *start_time, const char *protocol_str);
void process_packet(unsigned char *buffer, int size, int packet_no, const struct timeval *start_time);
double get_elapsed_time(const struct timeval *start_time, const struct timeval *current_time);

int main() {
    unsigned char *buffer = (unsigned char *) malloc(65536);

    if (!buffer) {
        fprintf(stderr, "Failed to allocate memory.\n");

        return EXIT_FAILURE;
    }
    //raw socket
    int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0) {
        perror("Socket Error");
        free(buffer);
        return EXIT_FAILURE;
    }

    //keep track of the start time because wireshark calculates time as the current time since the program is executed
    struct timeval start_time;
    //gettimeofday will fill in start_time with the exact time in seconds.microseconds
    gettimeofday(&start_time, NULL);
    printf("%5s %10s %-7s %-15s %-15s %7s\n",
           "No.", "Time", "Proto", "Source", "Destination", "Length");
    printf("--------------------------------------------------------------------------------\n");

    //start at 0 so that we can increment as soon as we see a packet come in. once we do, process it
    int packet_no = 0;
    struct sockaddr saddr;
    int saddr_size = sizeof(saddr);
    while (1) {
        // receive a raw ethernet frame
        int data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, (socklen_t *)&saddr_size);
        if (data_size < 0) {
            perror("Recvfrom Error");
            break;
        }
        //every packet gets a unique number (will be updated in the struct once we process it)
        packet_no++;
        process_packet(buffer, data_size, packet_no, &start_time);
    }

    close(sock_raw);
    free(buffer);
    return EXIT_SUCCESS;
}

void process_packet(unsigned char *buffer, int size, int packet_no, const struct timeval *start_time) {
    //recvfrom is gonna give us a raw ethernet header so we unpack it
    //iphdr contains all the info ab ip
    struct iphdr *ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));

    //using our struct, fill everything in and print it out
    PacketInfo pkt_info;
    struct sockaddr_in src_addr, dest_addr;

    //make space for source and dest
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.sin_addr.s_addr = ip_header->saddr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_addr.s_addr = ip_header->daddr;

    //convert ip address to string for both source and destination
    inet_ntop(AF_INET, &(src_addr.sin_addr), pkt_info.src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(dest_addr.sin_addr), pkt_info.dest_ip, INET_ADDRSTRLEN);

    //update the protocol
    const char *protocol_str;
    switch (ip_header->protocol) {
        case PROTOCOL_ICMP:
            pkt_info.protocol = PROTOCOL_ICMP;
            protocol_str = "ICMP";
            break;
        case PROTOCOL_IGMP:
            pkt_info.protocol = PROTOCOL_IGMP;
            protocol_str = "IGMP";
            break;
        case PROTOCOL_TCP:
            pkt_info.protocol = PROTOCOL_TCP;
            protocol_str = "TCP";
            break;
        case PROTOCOL_UDP:
            pkt_info.protocol = PROTOCOL_UDP;
            protocol_str = "UDP";
            break;
        default:
            pkt_info.protocol = PROTOCOL_OTHER;
            protocol_str = "OTHER";
            break;
    }
    //add the timestamp, packet number (which is alr incremented), size, and print it out
    gettimeofday(&pkt_info.timestamp, NULL);
    pkt_info.packet_no = packet_no;
    pkt_info.size = size;

    //print it
    print_packet_summary(&pkt_info, start_time, protocol_str);
}

void print_packet_summary(const PacketInfo *pkt_info, const struct timeval *start_time, const char *protocol_str) {
    double elapsed_time = get_elapsed_time(start_time, &pkt_info->timestamp);

    printf("%5d %10.6f %-7s %-15s %-15s %7d\n",
           pkt_info->packet_no,
           elapsed_time,
           protocol_str,
           pkt_info->src_ip,
           pkt_info->dest_ip,
           pkt_info->size);
}

double get_elapsed_time(const struct timeval *start_time, const struct timeval *current_time) {
    double elapsed = (current_time->tv_sec - start_time->tv_sec) +
                     (current_time->tv_usec - start_time->tv_usec) / 1e6;
    return elapsed;
}
