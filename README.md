# PcapParser
This automation analyzes network traffic from a pcap file using Python Scapy library.

This automation written in Python 3.8 with PyCharm on Ubuntu 20.04.

## Usage:
Before running this automation, please copy your pcap files to PCAPFiles directory and then do the next steps:

Open a terminal:

```$ python3 main.py```

choose the wanted file and then press enter.

## Features:

1.	Capturing Network Traffic: surfing to the http://example.com website and captures the network traffic using Wireshark, saving it to a pcap file for further analysis.

2.	Parsing the Pcap File: This automation reads the pcap file and uses Scapy library to parse the packets.

3.	Packets Count: The automation analyzes the total number of packets in the pcap file.

4.	Sessions Count: The automation analyzes the number of TCP and UDP sessions established during the browsing activity.

5.	DNS Queries: The automation analyzes DNS queries to determine the number of DNS queries made during the browsing session.

6.	TCP Flow: Using the parsed packet data, the automation represents the TCP flow for HTTP requests and responses.
