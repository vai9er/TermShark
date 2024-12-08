#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif // _DEFAULT_SOURCE

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
#include <ncurses.h>
#include <inttypes.h>
#include <pcap/pcap.h>

#include "filter.h"

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
    unsigned char *buf;
    char src_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    uint32_t seq;            // Sequence number
    uint32_t ack_seq;        // Acknowledgement number
    uint16_t src_port;
    uint16_t dest_port;
    uint8_t tcp_flags;
    int size;
} PacketInfo;

#define MAX_PACKETS 100000  // adjust as needed

PacketInfo *packet_list[MAX_PACKETS+1];
PacketInfo *filtered_packet_list[MAX_PACKETS+1];
int packet_count = 0;
int filtered_packet_count = 0;
int cursor_position = 0;  // index of the currently selected packet
int paused = 0;
int imported = 0;

FILE *log;

Filters filter_list = { 0 };

void print_packets(WINDOW *win, const struct timeval *start_time);
void process_packet(WINDOW *win, unsigned char *buffer, int size, int packet_no, const struct timeval *start_time);
double get_elapsed_time(const struct timeval *start_time, const struct timeval *current_time);
const char* get_protocol_str(ProtocolType protocol);
void tcp_trace(PacketInfo *packet, WINDOW *win, const struct timeval *start_time);
int is_same_tcp_stream(PacketInfo *p1, PacketInfo *p2);
void display_packet(WINDOW *win, PacketInfo *info);
void type_filter_box(WINDOW *win);
int match_filters(Filters *filters, PacketInfo *info);
void type_export(WINDOW *win);
void type_import(WINDOW *win);
void import_from_pcapng(const char *filename);
void export_to_pcapng(const char *filename);

int list_count() {
    int count = packet_list;
    if (filter_list.list_size > 0) {
        count = filtered_packet_count;
    }
    return count;
}

PacketInfo **get_list() {
    PacketInfo **list = &packet_list[0];
    if (filter_list.list_size > 0) {
        list = &filtered_packet_list[0];
    }
    return list;
}


int main(int argc, char** argv) {
    unsigned char *buffer = (unsigned char *) malloc(65536);

    log = fopen("log.out", "w");
    if (!buffer) {
        fprintf(stderr, "Failed to allocate memory.\n");
        return EXIT_FAILURE;
    }

    // start ncurses
    initscr();
    noecho();
    cbreak(); // line buffering disabled
    curs_set(FALSE);
    start_color();
    keypad(stdscr, TRUE);  // enable function keys and arrow keys
    nodelay(stdscr, TRUE); // non-blocking input

    // color pairs
    init_pair(1, COLOR_YELLOW, COLOR_BLACK);    // Header
    init_pair(2, COLOR_GREEN, COLOR_BLACK);     // TCP
    init_pair(3, COLOR_BLUE, COLOR_BLACK);      // UDP
    init_pair(4, COLOR_MAGENTA, COLOR_BLACK);   // ICMP
    init_pair(5, COLOR_RED, COLOR_BLACK);       // OTHER

    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);

    // create a window for displaying packets
    int win_height = max_y - 2; // leave space for borders
    int win_width = max_x - 2;
    int win_starty = 1; // start at line 1
    int win_startx = 1;

    move(win_starty, win_startx); // move the cursor to the beginning of the filter box
    WINDOW *filter_win = newwin(3, win_width*3/4, win_starty, win_startx);
    box(filter_win, 0, 0);
    WINDOW *info_win = newwin(win_height-2, win_width/4, win_starty+3, win_startx+win_width/2);
    box(info_win, 0, 0);
    WINDOW *packet_win = newwin(win_height-2, win_width/2, win_starty+3, win_startx);
    box(packet_win, 0, 0); // draw border
    scrollok(packet_win, TRUE); // allow scrolling
    wrefresh(packet_win);

    //raw socket
    int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0) {
        perror("Socket Error");
        free(buffer);
        endwin();
        return EXIT_FAILURE;
    }

    

    //keep track of the start time because wireshark originally does elapsed time
    struct timeval start_time;
    //gettimeofday will fill in start_time with the exact time in seconds.microseconds
    gettimeofday(&start_time, NULL);

    //start at 0 so that we can increment as soon as we see a packet come in. once we do, process it
    int packet_no = 0;
    struct sockaddr saddr;
    int saddr_size = sizeof(saddr);
    while (1) {

        // scrolling stuff
        int ch = getch();
        wrefresh(filter_win);
        wrefresh(info_win);
        if (ch != ERR) {
            //listen for up arrow
            if (ch == KEY_UP) {
                if (cursor_position > 0) {
                    cursor_position--;
                    print_packets(packet_win, &start_time);
                }
            } else if (ch == KEY_DOWN) {
                //listen for down arrow
                if (cursor_position < list_count() - 1) {
                    cursor_position++;
                    print_packets(packet_win, &start_time);
                }
            } else if (ch == KEY_RIGHT) {
                display_packet(info_win, get_list()[cursor_position]);
            } else if (ch == 'p' || ch == 'P') {
                display_packet(packet_win, get_list()[cursor_position]);
            } else if (ch == 'f' || ch == 'F') {
                type_filter_box(filter_win);
                cursor_position = 0;
                print_packets(packet_win, &start_time);
            } else if (ch == 'q' || ch == 'Q') {
                // exit on 'q' key (we can change later)
                break;
            } else if (ch == 't' || ch == 'T') {
                PacketInfo *p = get_list()[cursor_position];
                if(p->protocol == PROTOCOL_TCP){
                    tcp_trace(p, packet_win, &start_time);
                }
                print_packets(packet_win, &start_time);
            } else if (ch == 18){
                paused = !paused; // toggle paused state
				if (paused) {
					mvprintw(0, 0, "Paused. Press Ctrl+R to resume.");
				} else {
					mvprintw(0, 0, "Listening...                     ");
                    for (int i = 0; i < packet_count; ++i) {
						free(packet_list[i]);
					}
                    filtered_packet_count = 0;
					packet_count = 0;
					packet_no = 0;
                    gettimeofday(&start_time, NULL);
                    werase(packet_win);
					box(packet_win, 0, 0);
					wrefresh(packet_win);
				}
				refresh();

            }else if (ch == 'e' || ch == 'E') {  
                type_export(filter_win);
            } else if (ch == 'i' || ch == 'I') {  
                imported = 1;
                int save_count = packet_count;
                int save_pos = cursor_position;
                packet_count = 0;
                cursor_position = 0;
                type_import(filter_win);
                if(imported){
                    print_packets(packet_win, &start_time);
                }
                else{
                    packet_count = save_count;
                    cursor_position = save_pos;
                }
            }   
        }

        // if (paused) {
		// 	usleep(1000);  // sleep briefly to avoid busy-waiting
		// 	continue;
		// }

        // receive a raw ethernet frame
        
        if(!paused && !imported){
            int data_size = recvfrom(sock_raw, buffer, 65536, MSG_DONTWAIT, &saddr, (socklen_t *)&saddr_size);
            if (data_size < 0) {
                if (errno == EWOULDBLOCK || errno == EAGAIN) {
                    // no data available, continue
                    usleep(1000);  // sleep for 1ms to avoid busy-waiting
                    continue;
                } else {
                    perror("Recvfrom Error");
                    break;
                }
            }
            // every packet gets a unique number
            packet_no++;
            process_packet(packet_win, buffer, data_size, packet_no, &start_time);
        }
        
    }

    close(sock_raw);
    free(buffer);
    for (int i = 0; i < packet_count; ++i) {
        free(packet_list[i]->buf);
        free(packet_list[i]);
    }
    endwin();
    fclose(log);
    return EXIT_SUCCESS;
}

void display_packet(WINDOW *win, PacketInfo *info) {
    struct ether_header *eth_header = (struct ether_header *)(info->buf);
    int current_row = 0;
    int max_y, max_x;
    getmaxyx(win, max_y, max_x);
    const int ethernet_fields = 4;
    char ethernet_format[ethernet_fields][100];
    int i = 0, j = 0;
    sprintf(ethernet_format[i++], "Ethernet Header");
    sprintf(ethernet_format[i++], "%-20s %.2x:%.2x:%.2x:%.2x:%.2x:%.2x", "Source", eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2], eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5]);
    sprintf(ethernet_format[i++], "%-20s %.2x:%.2x:%.2x:%.2x:%.2x:%.2x", "Destination", eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2], eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);
    sprintf(ethernet_format[i++], "%-20s %u", "Protocol", eth_header->ether_type);

    struct iphdr *ip_header = (struct iphdr *)(info->buf + sizeof(struct ether_header));
    struct sockaddr_in source,dest;

    source.sin_addr.s_addr = ip_header->saddr;
    dest.sin_addr.s_addr = ip_header->daddr;

    const int ip_fields = 12;
    char ipv4_format[ip_fields][100];
    i = 0;
    sprintf(ipv4_format[i++], "IP Header");
    sprintf(ipv4_format[i++], "%-20s %d", "Version", ip_header->version);
    sprintf(ipv4_format[i++], "%-20s %d", "Header Length", ip_header->ihl);
    sprintf(ipv4_format[i++], "%-20s %d", "Type of Service", ip_header->tos);
    sprintf(ipv4_format[i++], "%-20s %d", "Total Length", ip_header->tot_len);
    sprintf(ipv4_format[i++], "%-20s %d", "Identification", ip_header->id);
    sprintf(ipv4_format[i++], "%-20s %d", "Fragment Offset", ip_header->frag_off);
    sprintf(ipv4_format[i++], "%-20s %d", "TTL", ip_header->ttl);
    sprintf(ipv4_format[i++], "%-20s %d", "Protocol", ip_header->protocol);
    sprintf(ipv4_format[i++], "%-20s %d", "Checksum", ip_header->check);
    sprintf(ipv4_format[i++], "%-20s %s", "Source IP ", inet_ntoa(source.sin_addr));
    sprintf(ipv4_format[i++], "%-20s %s", "Destination IP", inet_ntoa(dest.sin_addr));


    const int tcp_fields = 16;
    struct tcphdr *tcp_header = (struct tcphdr *)(info->buf + sizeof(struct ether_header) + ip_header->ihl*4);
    char tcp_format[tcp_fields][100];

    i = 0;
    sprintf(tcp_format[i++], "TCP Header");
    sprintf(tcp_format[i++], "%-20s %d", "Source Port", ntohs(tcp_header->source));
    sprintf(tcp_format[i++], "%-20s %d", "Destination Port", ntohs(tcp_header->dest));
    sprintf(tcp_format[i++], "%-20s %u", "Sequence Number", ntohl(tcp_header->seq));
    sprintf(tcp_format[i++], "%-20s %u", "Acknowledge Number", ntohl(tcp_header->ack_seq));
    sprintf(tcp_format[i++], "%-20s %d", "Data Offset", ntohl(tcp_header->doff));
    sprintf(tcp_format[i++], "%-20s %d", "Urgent Flag", tcp_header->urg);
    sprintf(tcp_format[i++], "%-20s %d", "Acknowledgement Flag", tcp_header->ack);
    sprintf(tcp_format[i++], "%-20s %d", "Push Flag", tcp_header->psh);
    sprintf(tcp_format[i++], "%-20s %d", "Reset Flag", tcp_header->rst);
    sprintf(tcp_format[i++], "%-20s %d", "Sync Flag", tcp_header->syn);
    sprintf(tcp_format[i++], "%-20s %d", "Finish Flag", tcp_header->fin);
    sprintf(tcp_format[i++], "%-20s %d", "Finish Flag", tcp_header->fin);
    sprintf(tcp_format[i++], "%-20s %d", "Window", ntohs(tcp_header->window));
    sprintf(tcp_format[i++], "%-20s %d", "Checksum", ntohs(tcp_header->check));
    sprintf(tcp_format[i++], "%-20s %d", "Urgent Pointer", tcp_header->urg_ptr);

    char (*fields[])[100] = {ethernet_format, ipv4_format, tcp_format};
    #define num_headers 3
    int sizes[num_headers] = { ethernet_fields, ip_fields, tcp_fields };
    int total_fields = ethernet_fields + ip_fields + tcp_fields;
    while (1) {
        int key = getch();
        if (key == KEY_DOWN) {
            if (current_row < total_fields-1) current_row++;
        } else if (key == KEY_UP){
            if (current_row > 0) current_row--;
        } else if (key == 'q' || key == 'Q' || key == KEY_LEFT) {
            werase(win);
            box(win,0,0);
            wrefresh(win);
            break;
        }
        werase(win);
        box(win,0,0);
        const int tabsize = 4;
        int absolute_cursor = 0, draw_cursor = 0, first_row = 0;
        int lines_per_window = max_y - 2;
        if (current_row >= lines_per_window) 
            first_row = current_row - lines_per_window+1;
        for (i = 0; i < num_headers; i++) {
            int size = sizes[i];
            for (j = 0; j < size; j++) {
                int ts = j == 0 ? tabsize: tabsize*2;
                if (absolute_cursor >= first_row && absolute_cursor < first_row + lines_per_window) {
                    if (absolute_cursor == current_row)
                        wattron(win, A_REVERSE);
                    wattron(win, COLOR_PAIR(2));
                    mvwprintw(win, ++draw_cursor, ts, "%-40s", fields[i][j]);
                    wattroff(win, COLOR_PAIR(2));
                    wattroff(win, A_REVERSE);
                }
                absolute_cursor++;
            }
        }

        wrefresh(win);
    }
}

void process_packet(WINDOW *win, unsigned char *buffer, int size, int packet_no, const struct timeval *start_time) {

    struct iphdr *ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    unsigned short iphdrlen = ip_header->ihl * 4;

    PacketInfo *pkt_info = malloc(sizeof(PacketInfo));
    pkt_info->buf = malloc(sizeof(unsigned char)*size);
    memcpy(pkt_info->buf, buffer, size);
    pkt_info->ack_seq = -1;
    pkt_info->seq = -1;
    pkt_info->src_port = 0;
    pkt_info->dest_port = 0;
    pkt_info->tcp_flags = 0;

    if (!pkt_info) {
        fprintf(stderr, "Failed to allocate memory for PacketInfo.\n");
        return;
    }
    struct sockaddr_in src_addr, dest_addr;

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.sin_addr.s_addr = ip_header->saddr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_addr.s_addr = ip_header->daddr;

    inet_ntop(AF_INET, &(src_addr.sin_addr), pkt_info->src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(dest_addr.sin_addr), pkt_info->dest_ip, INET_ADDRSTRLEN);


    switch (ip_header->protocol) {
        case PROTOCOL_ICMP:
            pkt_info->protocol = PROTOCOL_ICMP;
            break;
        case PROTOCOL_IGMP:
            pkt_info->protocol = PROTOCOL_IGMP;
            break;
        case PROTOCOL_TCP: {
            pkt_info->protocol = PROTOCOL_TCP;
            struct tcphdr *tcp_header = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + iphdrlen);
            pkt_info->seq = ntohl(tcp_header->th_seq);
            pkt_info->ack_seq = ntohl(tcp_header->th_ack);
            pkt_info->src_port = ntohs(tcp_header->source);
            pkt_info->dest_port = ntohs(tcp_header->dest);
            pkt_info->tcp_flags = tcp_header->th_flags;
            break;
        }case PROTOCOL_UDP:
            pkt_info->protocol = PROTOCOL_UDP;
            break;
        default:
            pkt_info->protocol = PROTOCOL_OTHER;
            break;
    }
    // adding the timestamp, packet number, size
    gettimeofday(&pkt_info->timestamp, NULL);
    pkt_info->packet_no = packet_no;
    pkt_info->size = size;

    // store the packet info in the list
    if (packet_count < MAX_PACKETS) {
        packet_list[packet_count++] = pkt_info;
        for (int i = 0; i < filter_list.list_size; i++) {
            if (match_filters(&filter_list, pkt_info))
                filtered_packet_list[filtered_packet_count++] = pkt_info;
        }
    } else {
        // handle overflow, e.g., by reallocating or discarding old packets
        // naively discard the packets when the buffer is full
        free(pkt_info);
        return;
    }

    // print all packets up to the current one
    print_packets(win, start_time);
}

void print_packets(WINDOW *win, const struct timeval *start_time) {
    werase(win);  // clear window content
    box(win, 0, 0);  // draw border
    PacketInfo **list = &packet_list[0];
    int count = packet_count;
    if (filter_list.list_size > 0) {
        list = &filtered_packet_list[0];
        count = filtered_packet_count;
    }

    // print headers
    wattron(win, COLOR_PAIR(1) | A_BOLD);
    mvwprintw(win, 1, 1, "%5s %10s %-7s %-15s %-15s %7s",
              "No.", "Time", "Proto", "Source", "Destination", "Length");
    wattroff(win, COLOR_PAIR(1) | A_BOLD);

    int max_y, max_x;
    getmaxyx(win, max_y, max_x);

    int start_line = 2;  // line where packet info starts
    int lines_per_page = max_y - start_line - 1;  // space for borders

    int first_packet = 0;
    int last_packet = packet_count;

    // iwhen the cursor needs to go outside the box
    if (cursor_position >= first_packet + lines_per_page) {
        first_packet = cursor_position - lines_per_page + 1;
    }
    if (cursor_position < first_packet) {
        first_packet = cursor_position;
    }
    last_packet = first_packet + lines_per_page;
    if (last_packet > count) {
        last_packet = count;
    }

    for (int i = first_packet; i < last_packet; ++i) {
        PacketInfo *pkt_info = list[i];
        double elapsed_time = get_elapsed_time(start_time, &pkt_info->timestamp);

        int color_pair;
        switch (pkt_info->protocol) {
            case PROTOCOL_TCP:
                color_pair = 2;
                break;
            case PROTOCOL_UDP:
                color_pair = 3;
                break;
            case PROTOCOL_ICMP:
                color_pair = 4;
                break;
            default:
                color_pair = 5;
                break;
        }

        // highlight the selected packet
        if (i == cursor_position) {
            wattron(win, A_REVERSE);  // Highlighted
        }

        wattron(win, COLOR_PAIR(color_pair));
        mvwprintw(win, start_line + i - first_packet, 1, "%5d %10.6f %-7s %-15s %-15s %7d",
                  pkt_info->packet_no,
                  elapsed_time,
                  get_protocol_str(pkt_info->protocol),
                  pkt_info->src_ip,
                  pkt_info->dest_ip,
                  pkt_info->size);
        wattroff(win, COLOR_PAIR(color_pair));

        if (i == cursor_position) {
            wattroff(win, A_REVERSE);
        }
    }

    wrefresh(win);
}

double get_elapsed_time(const struct timeval *start_time, const struct timeval *current_time) {
    return (current_time->tv_sec - start_time->tv_sec) + (current_time->tv_usec - start_time->tv_usec) / 1e6;
}

const char* get_protocol_str(ProtocolType protocol) {
    switch (protocol) {
        case PROTOCOL_ICMP:
            return "ICMP";
        case PROTOCOL_IGMP:
            return "IGMP";
        case PROTOCOL_TCP:
            return "TCP";
        case PROTOCOL_UDP:
            return "UDP";
        default:
            return "OTHER";
    }
}

int match_filters(Filters *filters, PacketInfo *info) {
    for (int i = 0; i < filter_list.list_size; i++) {
        FilterItem *item = &filter_list.filters[i];
        int b;
        switch (item->field) {
            case FILTER_PROTOCOL:
                b = strcasecmp(item->value, get_protocol_str(info->protocol)) == 0;
                break;
            case FILTER_SOURCE_IP:
                b = strcasecmp(item->value, info->src_ip) == 0;
                break;
            case FILTER_DESTINATION_IP:
                b = strcasecmp(item->value, info->dest_ip) == 0;
                break;
            default:
                b = 0;
                break;
        }
        if (item->negate) b = !b;

        if (!b) {
            return FALSE;
        }
    } 
    return TRUE;
}

void type_filter_box(WINDOW *win) {
    curs_set(TRUE);
    int ch;
    while ((ch = getch()) != '\n') {
        werase(win);
        box(win,0,0);
        mvwprintw(win, 1, 1, filter_list.filter_string);
        if (ch == KEY_BACKSPACE || ch == KEY_DC || ch == 127 || ch == '\b') {
            if (filter_list.filter_pos > 0) {
                filter_list.filter_pos--;
                filter_list.filter_string[filter_list.filter_pos] = '\0';
            }
        } else if (ch >= 32 && ch <= 126) {
            if (filter_list.filter_pos < MAX_FILTER_LEN) {
                filter_list.filter_string[filter_list.filter_pos++] = ch;
                filter_list.filter_string[filter_list.filter_pos] = '\0';
            }
        }

        // move(1, 2 + filter_pos);
        wrefresh(win);
    }
    curs_set(FALSE);
    
    char *s = filter_list.filter_string;
    int i = 0;
    filter_list.list_size = 0;
    // parse filter string
    while (*s != '\0') {
        while (*s == ' ') s++;
        
        FilterItem *item = &filter_list.filters[filter_list.list_size];
        item->negate = FALSE; 
        if (*s == '!') {
            item->negate = TRUE; 
            s++;
        }

        int match = FALSE;
        // identify which filter it is
        if (strlen(s) >= 4 && strncmp(s, "src=", 4) == 0) {
            item->field = FILTER_SOURCE_IP;
            match = TRUE;
            s += 4;
        } else if (strlen(s) >= 4 && strncmp(s, "dst=", 4) == 0) {
            item->field = FILTER_DESTINATION_IP;
            match = TRUE;
            s += 4;
        } else if (strlen(s) >= 6 && strncmp(s, "proto=", 6) == 0) {
            item->field = FILTER_PROTOCOL;
            match = TRUE;
            s += 6;
        }

        // skip if not matching any of the predefined filters
        if (!match) {
            s++;
            continue;
        }

        i = 0;
        // copy the value of the string into the filter
        while (*s != '\0' && *s != ' ') {
            item->value[i++] = *s;
            s++;
        }
        item->value[i] = '\0';

        fflush(log);
        filter_list.list_size++;
    }

    filtered_packet_count = 0;
    for (int i = 0; i < packet_count; i++) {
        if (match_filters(&filter_list, packet_list[i])) {
            filtered_packet_list[filtered_packet_count++] = packet_list[i];
        }
    }
}

int is_same_tcp_stream_forward(PacketInfo *p1, PacketInfo *p2) {
    if (p1->protocol != PROTOCOL_TCP || p2->protocol != PROTOCOL_TCP)
        return 0;
    if (((strcmp(p1->src_ip, p2->src_ip) == 0 && p1->src_port == p2->src_port &&
          strcmp(p1->dest_ip, p2->dest_ip) == 0 && p1->dest_port == p2->dest_port &&
          p1->seq <= p2->seq)
        ||
         (strcmp(p1->src_ip, p2->dest_ip) == 0 && p1->src_port == p2->dest_port &&
          strcmp(p1->dest_ip, p2->src_ip) == 0 && p1->dest_port == p2->src_port &&
          p1->ack_seq <= p2->ack_seq)))
    {
        return 1;
    }
    return 0;
}

int is_same_tcp_stream_back(PacketInfo *p1, PacketInfo *p2) {
    if (p1->protocol != PROTOCOL_TCP || p2->protocol != PROTOCOL_TCP)
        return 0;
    if (((strcmp(p1->src_ip, p2->src_ip) == 0 && p1->src_port == p2->src_port &&
          strcmp(p1->dest_ip, p2->dest_ip) == 0 && p1->dest_port == p2->dest_port &&
          p1->seq >= p2->seq)
        ||
         (strcmp(p1->src_ip, p2->dest_ip) == 0 && p1->src_port == p2->dest_port &&
          strcmp(p1->dest_ip, p2->src_ip) == 0 && p1->dest_port == p2->src_port &&
          p1->ack_seq >= p2->ack_seq)))
    {
        return 1;
    }
    return 0;
}


void tcp_trace(PacketInfo *packet, WINDOW *win, const struct timeval *start_time){
    PacketInfo *stream_packets[MAX_PACKETS];
    int stream_packet_count = 0;
    stream_packets[0] = packet_list[cursor_position];
    int syn_found = 0;

    for (int i = cursor_position-1; i >= 0; i--) {
        if (is_same_tcp_stream_back(packet, packet_list[i])) {
            if(syn_found && !(packet_list[i]->tcp_flags & TH_SYN)){
                break;
            }

            for(int j = stream_packet_count; j >= 0; j--){
                stream_packets[j+1] = stream_packets[j];
            }
            
            stream_packets[0] = packet_list[i];
            stream_packet_count++;
            if(packet_list[i]->tcp_flags & TH_SYN){
                syn_found = 1;
            }
        }
    }

    for (int i = cursor_position; i < packet_count; ++i) {
        if (is_same_tcp_stream_forward(packet, packet_list[i])) {
            stream_packets[stream_packet_count++] = packet_list[i];
            if(packet_list[i]->tcp_flags & TH_FIN){
                break;
            }
        }
    }

    int tcp_cursor_position = 0;
    while (1) {
        int ch = getch();
        if (ch == KEY_UP) {
            if (tcp_cursor_position > 0) {
                tcp_cursor_position--;
            }
        } else if (ch == KEY_DOWN) {
            if (tcp_cursor_position < stream_packet_count -1) {
                tcp_cursor_position++;
            }
        } else if (ch == 'b' || ch == 'B') {
            break;  
        }
        werase(win);  
        box(win, 0, 0); 
        mvwprintw(win, 0, 0, "Following TCP Stream press \"b\" to go back to capture ");
        wattron(win, COLOR_PAIR(1) | A_BOLD);
        mvwprintw(win, 1, 1, "%5s %10s %-7s %-15s %-15s %7s",
                    "No.", "Time", "Proto", "Source", "Destination", "Length");
        wattroff(win, COLOR_PAIR(1) | A_BOLD);

        int max_y, max_x;
        getmaxyx(win, max_y, max_x);

        int start_line = 2;  
        int lines_per_page = max_y - start_line - 1;

        int first_packet = 0;
        int last_packet = stream_packet_count;

        if (tcp_cursor_position >= first_packet + lines_per_page) {
            first_packet = tcp_cursor_position - lines_per_page + 1;
        }
        if (tcp_cursor_position < first_packet) {
            first_packet = tcp_cursor_position;
        }
        last_packet = first_packet + lines_per_page;
        if (last_packet > stream_packet_count) {
            last_packet = stream_packet_count;
        }

        for (int i = first_packet; i < last_packet; ++i) {
            PacketInfo *pkt_info = stream_packets[i];
            double elapsed_time = get_elapsed_time(start_time, &pkt_info->timestamp);

            int color_pair = 2;

            if (i == tcp_cursor_position) {
                wattron(win, A_REVERSE); 
            }

            wattron(win, COLOR_PAIR(color_pair));
            mvwprintw(win, start_line + i - first_packet, 1, "%5d %10.6f %-7s %-15s %-15s %7d %" PRIu32 " %" PRIu32 " %" PRIu8,
                      pkt_info->packet_no,
                      elapsed_time,
                      get_protocol_str(pkt_info->protocol),
                      pkt_info->src_ip,
                      pkt_info->dest_ip,
                      pkt_info->size,
                      pkt_info->seq,
                      pkt_info->ack_seq,
                      pkt_info->tcp_flags);
            wattroff(win, COLOR_PAIR(color_pair));

            if (i == tcp_cursor_position) {
                wattroff(win, A_REVERSE);
            }
        }
        wrefresh(win);
    }
}


void export_to_pcapng(const char *filename) {
    pcap_t *handle;
    pcap_dumper_t *dumper;
    
    handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (!handle) {
        mvprintw(0, 0,  "Failed to open pcap handle.\n");
        return;
    }

    dumper = pcap_dump_open(handle, filename);
    if (!dumper) {
        mvprintw(0, 0, "Failed to open pcapng file: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return;
    }

    for (int i = 0; i < packet_count; i++) {
        struct pcap_pkthdr header;
        header.ts = (struct timeval)packet_list[i]->timestamp;
        header.caplen = packet_list[i]->size;
        header.len = packet_list[i]->size;
        
        pcap_dump((unsigned char *)dumper, &header, packet_list[i]->buf);
    }

    pcap_dump_close(dumper);
    pcap_close(handle);
}


void import_from_pcapng(const char *filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(filename, errbuf);

    if (!handle) {
        mvprintw(0, 0, "Failed to open pcapng file: %s", errbuf);
        imported = 0;
        return;
    }

    struct pcap_pkthdr *header;
    const unsigned char *data;
    int packet_no = 0;

    while (pcap_next_ex(handle, &header, &data) > 0) {

        PacketInfo *pkt_info = malloc(sizeof(PacketInfo));
        pkt_info->buf = malloc(sizeof(unsigned char)*header->caplen);
        memcpy(pkt_info->buf, data, header->caplen);


        struct iphdr *ip_header = (struct iphdr *)(data + sizeof(struct ethhdr));
        unsigned short iphdrlen = ip_header->ihl * 4;
        memcpy(pkt_info->buf, data, header->caplen);
        pkt_info->ack_seq = -1;
        pkt_info->seq = -1;
        pkt_info->src_port = 0;
        pkt_info->dest_port = 0;
        pkt_info->tcp_flags = 0;
        pkt_info->timestamp = (struct timeval)header->ts;

        if (!pkt_info) {
            mvprintw(0, 0, "Failed to allocate memory for PacketInfo.");
            imported = 0;
            return;
        }
        struct sockaddr_in src_addr, dest_addr;

        memset(&src_addr, 0, sizeof(src_addr));
        src_addr.sin_addr.s_addr = ip_header->saddr;
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.sin_addr.s_addr = ip_header->daddr;

        inet_ntop(AF_INET, &(src_addr.sin_addr), pkt_info->src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(dest_addr.sin_addr), pkt_info->dest_ip, INET_ADDRSTRLEN);


        switch (ip_header->protocol) {
            case PROTOCOL_ICMP:
                pkt_info->protocol = PROTOCOL_ICMP;
                break;
            case PROTOCOL_IGMP:
                pkt_info->protocol = PROTOCOL_IGMP;
                break;
            case PROTOCOL_TCP: {
                pkt_info->protocol = PROTOCOL_TCP;
                struct tcphdr *tcp_header = (struct tcphdr *)(data + sizeof(struct ethhdr) + iphdrlen);
                pkt_info->seq = ntohl(tcp_header->th_seq);
                pkt_info->ack_seq = ntohl(tcp_header->th_ack);
                pkt_info->src_port = ntohs(tcp_header->source);
                pkt_info->dest_port = ntohs(tcp_header->dest);
                pkt_info->tcp_flags = tcp_header->th_flags;
                break;
            }case PROTOCOL_UDP:
                pkt_info->protocol = PROTOCOL_UDP;
                break;
            default:
                pkt_info->protocol = PROTOCOL_OTHER;
                break;
        }
        pkt_info->packet_no = ++packet_no;
        pkt_info->size = header->caplen;

        if (packet_count < MAX_PACKETS) {
            packet_list[packet_count++] = pkt_info;
        } else {
            free(pkt_info);
            return;
        }

    }

    pcap_close(handle);
}


void type_export(WINDOW *win) {
    curs_set(TRUE);
    int ch;
    char buf[MAX_FILTER_LEN];
    buf[0] = '\0';
    int bufpos = 0;
    while ((ch = getch()) != '\n') {
        werase(win);
        box(win,0,0);
        mvwprintw(win, 1, 1, buf);
        if (ch == KEY_BACKSPACE || ch == KEY_DC || ch == 127 || ch == '\b') {
            if (bufpos > 0) {
                bufpos--;
                buf[bufpos] = '\0';
            }
        } else if (ch >= 32 && ch <= 126) {
            if (bufpos < MAX_FILTER_LEN) {
                buf[bufpos++] = ch;
                buf[bufpos] = '\0';
            }
        }
        wrefresh(win);
    }
    curs_set(FALSE);
    char *s = buf;
    export_to_pcapng(s);
}

void type_import(WINDOW *win) {
    curs_set(TRUE);
    int ch;
    char buf[MAX_FILTER_LEN];
    buf[0] = '\0';
    int bufpos = 0;
    while ((ch = getch()) != '\n') {
        werase(win);
        box(win,0,0);
        mvwprintw(win, 1, 1, buf);
        if (ch == KEY_BACKSPACE || ch == KEY_DC || ch == 127 || ch == '\b') {
            if (bufpos > 0) {
                bufpos--;
                buf[bufpos] = '\0';
            }
        } else if (ch >= 32 && ch <= 126) {
            if (bufpos < MAX_FILTER_LEN) {
                buf[bufpos++] = ch;
                buf[bufpos] = '\0';
            }
        }
        wrefresh(win);
    }
    curs_set(FALSE);
    char *s = buf;
    import_from_pcapng(s);
}