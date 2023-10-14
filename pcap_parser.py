from scapy.all import rdpcap, PcapReader, Raw
from scapy.layers.http import HTTP
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS
from Functions import Functions
from logger import Logger
from scapy.plist import PacketList


class PcapParser:
    def __init__(self, pcap_file_path):
        self.functions = Functions()
        self.pcap_file_path = pcap_file_path
        self.logger = Logger(self.__class__.__name__)

    def parse_pcap_file(self) -> PacketList:
        """
        This function parses a pcap file.
        :return: A list of packets.
        """
        try:
            parsed_file = rdpcap(self.pcap_file_path)
            return parsed_file

        except Exception as err:
            self.logger.logger.error(err)
            raise PcapParserError(f"Error while parsing pcap file '{self.pcap_file_path}': {err}")

    def get_count_of_packets(self) -> int:
        """
        This function returns the count of packets in a pcap file.
        In Wireshark: Statistic >> Packet Lengths
        :return: The number of packets.
        """
        try:
            packet_list = self.parse_pcap_file()
            count_of_packets = len(packet_list)

            self.logger.logger.info(f"The count of packets in '{self.pcap_file_path}': {count_of_packets}")
            return count_of_packets

        except Exception as err:
            self.logger.logger.error(err)
            raise PcapParserError(f"Unable to return the count of packets in {self.pcap_file_path}: {err}")

    def get_count_of_sessions(self) -> int:
        """
        This function returns the count of sessions in a pcap file.
        In Wireshark: Statistic >> Conversations.
        :return: The number of sessions.
        """
        try:
            sessions = set()
            with PcapReader(self.pcap_file_path) as pcap:
                for packet in pcap:
                    if IP in packet and (TCP in packet or UDP in packet):
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst

                        if TCP in packet:
                            src_port = packet[TCP].sport
                            dst_port = packet[TCP].dport
                        elif UDP in packet:
                            src_port = packet[UDP].sport
                            dst_port = packet[UDP].dport

                    session_key = (src_ip, src_port, dst_ip, dst_port)
                    sessions.add(session_key)

            self.logger.logger.info(f"The count of sessions in '{self.pcap_file_path}': {len(sessions)}")
            return len(sessions)

        except Exception as err:
            self.logger.logger.error(err)
            raise PcapParserError(f"Unable to return the count of sessions in '{self.pcap_file_path}': {err}")

    def get_count_of_dns_queries(self) -> int:
        """
        This function returns the count of dns queries in a pcap file.
        In Wireshark: Statistic >> DNS.
        :return: The number of dns queries.
        """
        try:
            pcap_file = self.parse_pcap_file()
            dns_queries_count = 0
            for packet in pcap_file:
                if DNS in packet:
                    dns_queries_count += 1

            self.logger.logger.info(f"The count of DNS queries in '{self.pcap_file_path}': {dns_queries_count}")
            return dns_queries_count

        except Exception as err:
            self.logger.logger.error(err)
            raise PcapParserError(f"Unable to return the count of dns queries in '{self.pcap_file_path}': {err}")

    def tcp_flow(self) -> None:
        """
        This function represents the TCP-FLOW and creates a json file that contain an array of dictionaries,
         where each dictionary represents a TCP flow with its associated HTTP requests and responses.
        :return: None
        """
        try:
            http_process_data = []
            pcap_file = self.parse_pcap_file()
            tcp_flows = {}

            # This loop checks each packet in the pcap_file, filters TCP packets with raw data to represent the
            # TCP flow.
            for packet in pcap_file:
                if TCP in packet and packet.haslayer(Raw):
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport

                    flow_key = f"{src_ip}:{src_port} - {dst_ip}:{dst_port}"
                    if flow_key not in tcp_flows:
                        tcp_flows[flow_key] = []

                    tcp_flows[flow_key].append(packet)

            # This loop checks each TCP flow in tcp_flows and groups packets into the request and response lists
            # based on HTTP layer.
            for flow_key, flow_packets in tcp_flows.items():
                requests = []
                responses = []

                for packet in flow_packets:
                    if packet.haslayer(HTTP):
                        if packet[TCP].sport == ParserArguments.PORT_80:  # requests have source port 80
                            requests.append(packet.summary())
                        else:  # responses have destination port 80
                            responses.append(packet.summary())

                flow_data = {
                    ParserArguments.FLOW_KEY: flow_key,
                    ParserArguments.REQUESTS: requests,
                    ParserArguments.RESPONSES: responses
                }
                http_process_data.append(flow_data)

                # filter out keys with empty Requests and Responses
                http_process_data = [key for key in http_process_data if key[ParserArguments.REQUESTS] or
                                     key[ParserArguments.RESPONSES]]

            self.functions.create_json_file(ParserArguments.HTTP_FLOW_FILE, http_process_data)
            self.logger.logger.info(f"The TCP-FLOW is in: {ParserArguments.HTTP_FLOW_FILE} file.")

        except Exception as err:
            self.logger.logger.error(err)
            raise PcapParserError(f"Unable to return the TCP-Flow: {err}")

    def run(self) -> None:
        """
        This function runs all the methods that mention above.
        :return: None
        """
        try:
            # count of packets
            packets = self.get_count_of_packets()
            print(f"\nThe count of packets in '{self.pcap_file_path}': {packets}\n")

            # count of sessions
            sessions = self.get_count_of_sessions()
            print(f"The count of sessions in '{self.pcap_file_path}': {sessions}\n")

            # count of dns queries
            dns_queries = self.get_count_of_dns_queries()
            print(f"The count of DNS queries in '{self.pcap_file_path}': {dns_queries}\n")

            # TCP-FLOW
            self.tcp_flow()
            print(f"The TCP-FLOW is in: {ParserArguments.HTTP_FLOW_FILE} file.")

        except Exception as err:
            self.logger.logger.error(err)
            raise PcapParserError(f"Unable to run {self.__class__.__name__}, Error: {err}")


class ParserArguments:

    HTTP_FLOW_FILE = "tcp_flow.json"
    PCAP_FILE_ROOT_DIR = "PCAPFiles"

    COUNT_FROM_0 = 0
    PLUS_ONE = 1

    FLOW_KEY = "flow_key"
    REQUESTS = "Requests"
    RESPONSES = "Responses"

    PORT_80 = 80


class PcapParserError(Exception):
    pass
