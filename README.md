# D58-Final-Project
Packet Sniffer in C


Ben Wilson 1007289024 wilos929

Gabriel Vaner 1007121204 vainerga


Ben's Contirbution:

TCP Stream Following:

    The user can select a TCP packet among the captured packets and press 't'
    to follow it's TCP stream. A list of all TCP packets sent between the 
    two host will be displayed.


    is_same_tcp_stream_forward(PacketInfo *p1, PacketInfo *p2):

        PacketInfo *p1: Pointer to the selected packet's information.
        PacketInfo *p2: Pointer to information of the packet we're checking is 
                        in the same stream as p1.

        Returns 1 if p1 and p2 belong to the same TCP stream.
        Returns 0 otherwise.

        Determines if two TCP packets, p1 and p2, belong to the same TCP stream where
        p2 is a packet captured after p1. 

        Compares the source and destination IPs and ports of both packets to verify a match.
        Ensures that the sequence number of p1 is less than or equal to that of p2 or the 
        acknowledgment sequence number of p1 is less than or equal to p2.
   
    is_same_tcp_stream_back(PacketInfo *p1, PacketInfo *p2):

        PacketInfo *p1: Pointer to the selected packet's information.
        PacketInfo *p2: Pointer to information of the packet we're checking is 
                        in the same stream as p1.

        Returns 1 if p1 and p2 belong to the same TCP stream.
        Returns 0 otherwise.

        Determines if two TCP packets, p1 and p2, belong to the same TCP stream where
        p2 is a packet captured before p1. 

        Compares the source and destination IPs and ports of both packets to verify a match.
        Ensures that the sequence number of p1 is less than or equal to that of p2 or the 
        acknowledgment sequence number of p1 is less than or equal to p2.

   
    tcp_trace(PacketInfo *packet, WINDOW *win, const struct timeval *start_time):
        
        PacketInfo *packet: Pointer to the starting packet for the trace.
        WINDOW *win: A pointer to the ncurses window used for displaying the trace.
        const struct timeval *start_time: Pointer to the start time of the capture for calculating elapsed time.

        Traces and displays the TCP stream associated with a given packet in an interactive user interface.
        Synchronizes and reconstructs TCP streams by identifying related packets based on sequence and acknowledgment numbers.
        Provides an interactive terminal-based UI for navigation and analysis of the TCP stream.

        Initializes a buffer stream_packets to store packets in the TCP stream.

        Traverses packets backward (from the current packet) using is_same_tcp_stream_back to identify related packets in the reverse direction.
        Stops when encountering a SYN packet or unrelated packet.

        Traverses packets forward (from the current packet) using is_same_tcp_stream_forward to identify related packets in the forward direction.
        Stops when encountering a FIN packet or unrelated packet.

        Displays the identified TCP stream in the win window interactively:
        The user can scroll up and down the list of packets using the arrow keys.
        Pressing b exits the view and returns to the capture screen.
        Highlights the currently selected packet and dynamically updates the view as the user navigates through the stream.


Importing and Exporting:

    The user can save the currently caputured packest to be viewed again later.

    export_to_pcapng(const char *filename):
        
        const char *filename:
        The path and filename where the PCAP-NG data will be saved.

        Exports the captured packets currently stored in packet_list to a specified PCAP-NG file.

        Creates/opens the specified PCAP-NG file and writes all packets from the packet_list to it.
        Each packet is written with a timestamp and its full captured length.
        If the pcap handle or PCAP-NG file cannot be opened, an error message is displayed.

    import_from_pcapng(const char *filename):

        const char *filename:
        The path and filename of the PCAP-NG file to be read and imported.

        Imports packets from a given PCAP-NG file into the packet_list
        
        Opens the specified PCAP-NG file for reading.
        Iterates through all packets, extracting the Ethernet and IP headers.
        Identifies protocols (ICMP, IGMP, TCP, UDP, or OTHER).
        For TCP packets, extracts sequence, acknowledgment numbers, ports, and flags.
        Converts IP addresses to human-readable format.
        Packs all information into PacketInfo structures and stores them in packet_list.
        Continues until all packets are read, or the maximum storage limit is reached.


Gabe's Contribution:
Core Packet Handling & Processing, Base functionality, and User Interface Setup, Pausing and Resuming Packets

    Struct PacketInfo
    PacketInfo is a structure that encapsulates all relevant information about a captured network packet. It includes:
    Timestamp: When the packet was captured.
    Packet Number: A unique identifier for each packet.
    Protocol: The type of protocol used (e.g., TCP, UDP).
    Buffer (buf): Pointer to the raw packet data.
    Source and Destination IPs: Human-readable IP addresses.
    TCP-Specific Fields: Sequence number, acknowledgment number, source and destination ports, and TCP flags.
    Size: The size of the packet in bytes.


    PacketInfo *packet_list[MAX_PACKETS+1];
    PacketInfo *filtered_packet_list[MAX_PACKETS+1];
    int packet_count = 0;
    int filtered_packet_count = 0;
    int cursor_position = 0;  // index of the currently selected packet
    int paused = 0;
    int imported = 0;
    FILE *log;

    Keeps the current state of the program including a list of the processed packets, a list of filtered packets, the current packet count of the program, as well as indicators for the        cursor and pause/resume state.

    int main(int argc, char** argv)
    This is the main function of the program that sets up a raw socket for packet capture, initializes the ncurses user interface, and handles user inputs for interacting with packets. It     continuously listens for packets using recvfrom(), processes them, and updates the UI for users to view or manipulate packet details.

    The main function is also responsible for determining whether we are paused (and should stop listening for packets) or to continously listen.

    void process_packet(WINDOW *win, unsigned char *buffer, int size, int packet_no, const struct timeval *start_time)
    This function processes a captured packet by extracting its headers and creating a PacketInfo structure containing the metadata. It adds the packet to the list of packets, applies         filters if any, and updates the packet list displayed in the ncurses window.

    void print_packets(WINDOW *win, const struct timeval *start_time)
    This function prints the respective summary list of captured packets in the ncurses window. It supports scrolling and highlights the currently selected packet, displaying details such 
    as the packet number, protocol, source/destination addresses, and length.

    double get_elapsed_time(const struct timeval *start_time, const struct timeval *current_time)
    This utility function calculates the elapsed time in seconds between the start time and the current packet's timestamp, used for tracking relative packet arrival times.
    
