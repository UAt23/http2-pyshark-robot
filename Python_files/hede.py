from queue import Empty
import pyshark


pcap_file_path = "D:\WORK\python_files\STOAMF1Pcap17001.pcap"

# def capture_shark(pcap_file_path):
    
# Sniff from interface
capture = pyshark.FileCapture(pcap_file_path, display_filter='tcp.port==5000')
# print(capture[0])
ip = []



for packet in capture:
    protocol = packet.transport_layer
    highest_layer = packet.highest_layer
    source_address = packet.ip.src
    source_port = packet[packet.transport_layer].srcport
    destination_address = packet.ip.dst
    destination_port = packet[packet.transport_layer].dstport
    packet_time = packet.sniff_time
    if packet.highest_layer == 'HTTP2':
        stream = packet.http2.stream
        if stream.find("HEADER")!=-1:
            header_value = packet.http2.header_value
            if hasattr(packet.http2, 'headers_path'):    
                header_path = packet.http2.headers_path
            if header_path.find("udm"):
                print('udm')
            if header_value == '201':
                print('SUCCESS')
    
    #return BuiltIn().log_to_console(capture[0])
    #rcc robot libs --pip --add pyshark==0.4.5 --conda conda.yaml