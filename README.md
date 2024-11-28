# D58-Final-Project
Packet Sniffer in C


Ben Wilson 1007289024 wilos929

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



