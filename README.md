<img src="https://i.imgur.com/lfq63nt.png">

## CLI-based Network Packet Analyzer written in C and ncurses!

## [Click Here for a Demonstration Video](https://www.youtube.com/watch?v=83gkPTmfcQU)


### Includes all of Your favourite WireShark Features straight from your terminal!
###### Note: This was submitted as a final project for CSCD58-Computer Networks at the University of Toronto

## Table of Contents
- [Features](#features)
  - [Live Sniffing (Left) && Scrolling (Right)](#live-sniffing-left--scrolling-right)
  - [Tracerouting/TCP Streaming](#traceroutingtcp-streaming)
  - [Packet Inspection](#packet-inspection)
  - [Filtering By Protocols](#filtering-by-protocols)
  - [Filter Out Protocols](#filter-out-protocols)
  - [Filtering by any Packet Field](#filtering-by-any-packet-field)
  - [Other Capture Features](#other-capture-features)
- [How to Compile and Run](#compilation)
- [Credits and Contributions](#credits-and-contributions)


<br />

## Features
### Live Captures (Left) && Scrolling (Right)
##### As soon as you start the program, you will see a live capture of all the incoming packets on your local network. You are also able to scroll through all of them
<kbd>![GIF](https://i.giphy.com/media/v1.Y2lkPTc5MGI3NjExcXN0M2hmN2p3aDU5c3pvbHlwdG5ibDI0cWlrNHVlZzh3bGh6bTBlaiZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/p1zOnkHwnZCaqIFfcD/giphy.gif)</kbd>  <kbd>![GIF](https://i.giphy.com/media/v1.Y2lkPTc5MGI3NjExd2xncHE2NzU1cHB6YWZsc3J2Z2IwdWZxazJwNHI4cnZ6dTVmdmt0aSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/H5g6RAZgfK3mo2rNE6/giphy.gif)</kbd>

### Tracerouting/TCP Streaming
##### Pressing `t` on a particular TCP packet will display its TCP stream i.e a list of all TCP packets sent between the two hosts

![GIF](https://i.giphy.com/media/v1.Y2lkPTc5MGI3NjExM3NpYzIzajFldXU0emU3Nnd2ZnFjNXlvNmhmdmExcWoxNnVybzB1dSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/U2daJMreqZmijUsEEq/giphy.gif)  

### Packet Inspection
##### Pressing `->` on any packet allows you to visualize and inspect its protocol-specific headers 
###### (includes datagram segments for UDP and TCP)
![GIF](https://i.giphy.com/media/v1.Y2lkPTc5MGI3NjExcXJqbmQxM29tY2Q1enJ3OGhycG53bTU0OWRrcmFyNGVrOHg0YjU2cyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/oV0hXdfVMRd45UFQoo/giphy.gif)

### Live Filtering By Protocols

##### Pressing `f` and typing `proto={protocol}` will return you the capture with only the specified protocol
###### Note: Using UDP as an example

<kbd>![GIF](https://i.giphy.com/media/v1.Y2lkPTc5MGI3NjExMWE1Y3B2YXN6MTUzeW91eGVwZjZ4OHl2eXgyeWcxc3BnMGIxZHBnayZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/sqzCoUXlgYQ0GPauGP/giphy.gif)</kbd> 

### Live Filter-Out Protocols
##### Alternitavely, you can return the capture excluding the specified packet using `!proto={protocol}`
###### Note: Using TCP as an example
<kbd>![GIF](https://i.giphy.com/media/v1.Y2lkPTc5MGI3NjExMjdjdDl2cWQxaXA2aDY2eWFvemk0aDZhc2I0ZGlvd2xjcHF6Y3M1aSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/VEkX5yJfRq06oFyP7j/giphy.gif)</kbd>

### Live Filtering In/Out by Source Addresses
##### `[!]src={addr}`allows you to filter by valid source address within the capture
###### Note:! is optional
<kbd>![GIF](https://i.giphy.com/media/v1.Y2lkPTc5MGI3NjExOHZ5d3ExMXI4OWVseDlnM3h5OXl4Ymd5dWxlMDBhczZ0bmx2NzRnNSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/iIuSeSO11YnVclfJoA/giphy.gif)</kbd>

### Other Capture Features
- `e` and `i` for Importing/Exporting Capture Sessions respectively
- `ctrl-r` for Live Pausing and Resuming Captures

### Compilation
`sh compile.sh && sudo ./sniffer`

# Credits and Contributions
Ben Wilson, Gabriel Vaner, and Howard Yang

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
Core Packet Handling & Processing, Base functionality, UI Setup in Ncurses, Pausing and Resuming Packets

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

    Keeps the current state of the program including a list of the processed packets, a list of filtered packets, the current packet count of the program, as well as indicators for the cursor and pause/resume state.

    int main(int argc, char** argv)
    Sets up a raw socket for packet capture, initializes the ncurses user interface and draws the neccesary components, and handles user inputs for interacting with packets. It continuously listens for packets using recvfrom(), processes them, and updates the UI for users to view or manipulate packet details, as well as determines whether we are paused (and should stop listening for packets) or to continously listen.

    void process_packet(WINDOW *win, unsigned char *buffer, int size, int packet_no, const struct timeval *start_time)
    Processses a captured packet by extracting its headers and creating a PacketInfo structure containing the metadata. It adds the packet to the list of packets, applies  filters if any, and updates the packet list displayed in the ncurses window.

    void print_packets(WINDOW *win, const struct timeval *start_time)
    Prints the respective summary list of captured packets in the dedicated ncurses window. It supports scrolling and highlights the currently selected packet, displaying details such 
    as the packet number, protocol, source/destination addresses, and length.

    double get_elapsed_time(const struct timeval *start_time, const struct timeval *current_time)
    Calculates the elapsed time in seconds between the start time and the current packet's timestamp, used for tracking relative packet arrival times.
    

Howard’s Contribution:
	Displaying packets:
	When the user presses the right arrow while selecting a packet, it will display more
    information in the right box. Pressing the up and down arrow keys allows scrolling.

	void display_packet(WINDOW *win, PacketInfo *info)
		WINDOW *win: The window in which the packet data will be displayed
		PacketInfo info: The packet to be displayed
	
	This function determines what headers are important to display by examining the
    protocol field of the info struct. The remainder is a while loop that displays the 
    current packet headers, and responds to directional arrow keys to enable. To exit 
    the while loop simply press the left arrow key.


    Filtering Packets:
    Pressing “F” while on the main packet list, moves the cursor to the top input text 
    box where you are able to type specific keywords that will filter the packet list.

    typedef struct FilterItem_t {
        enum FilterField field; // either source ip, destination ip or protocol
        int negate; // whether or not to negate
        char value[MAX_SEARCH_VALUE_LEN]; // the string to filter by
    } FilterItem;


    typedef struct Filters_t {
        int list_size; // the current number of filters
        FilterItem filters[100]; // the list of filters
        char filter_string[MAX_FILTER_LEN];
        int filter_pos;
    } Filters;

    int match_filters(Filters *filters, PacketInfo *info)
        Filters *filters: The list of filters
        PacketInfo *info: The packet to check against the filters
        returns True iff the packet matches all the filters

    This function is a helper for determining whether or not a packet is matching the 
    currently applied filters

    void type_filter_box(WINDOW *win)
        WINDOW *win: The window that will be typed

    This is the function responsible for reading keyboard inputs and saving the 
    contents of the filter string to a buffer. There is a loop that parses this string and 
    looks for keywords such as “src=”, “dst=”, and “proto=” and the subsequent value 
    to filter by. It also checks if the first character is a “!” and negates the 
    following expression, so “!src=127.0.0.1” is a valid filter.

