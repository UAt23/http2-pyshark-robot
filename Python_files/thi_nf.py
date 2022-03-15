from queue import Empty

import pyshark
import json
import codecs


pcap_file_path = "D:\WORK\python_files\STOAMF1Pcap17001.pcap"

def get_packet_details(packet):
    
    protocol = packet.transport_layer
    highest_layer = packet.highest_layer
    source_address = packet.ip.src
    source_port = packet[packet.transport_layer].srcport
    destination_address = packet.ip.dst
    destination_port = packet[packet.transport_layer].dstport
    packet_time = packet.sniff_time
    return f'Packet Timestamp: {packet_time}' \
           f'\nHighhest layer: {highest_layer}' \
           f'\nProtocol type: {protocol}' \
           f'\nSource address: {source_address}' \
           f'\nSource port: {source_port}' \
           f'\nDestination address: {destination_address}' \
           f'\nDestination port: {destination_port}\n'

def get_http2_request_packets(packet):
    
    if hasattr(packet, 'http2') and packet[packet.transport_layer].dstport == '8006':
        results = get_packet_details(packet)

def get_http2_respond_packets(packet):
    
    if hasattr(packet, 'http2') and packet.http2.stream.find("HEADER") != -1 and packet[packet.transport_layer].srcport == '8006' and packet[packet.transport_layer].dstport == '34784': # 
        if hasattr(packet.http2,'json_object'):
            if hasattr(packet.http2,'data_data'):
                json_data = packet.http2.data_data.replace(":","")
                json_object = json.loads(codecs.decode(json_data,'hex'))
                if json_object['nfInstances'][0]['nfStatus'] =='REGISTERED':
                    print('REGISTERED')
                    registered = True
        results = get_packet_details(packet)
        return results

def capture_shark(pcap_file_path):
    
    # Sniff from interface
    capture = pyshark.FileCapture(pcap_file_path, display_filter='tcp.port == 8006', decode_as={'tcp.port==8006':'http2'})  
    # packets = [pkt for pkt in capture._packets]
    # print(len(list(capture)))
    for packet in capture:
        results = get_http2_respond_packets(packet)
        if results is not None:
            print(results)
    return print('DONE')
capture_shark(pcap_file_path)