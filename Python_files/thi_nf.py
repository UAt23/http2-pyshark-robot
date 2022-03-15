from queue import Empty

import pyshark
import json
import codecs


pcap_file_path = "D:\WORK\python_files\STOAMF1Pcap17001.pcap"

def get_packet_details(packet):
    

    if hasattr(packet.http2,'json_object'):
            if hasattr(packet.http2,'data_data'):
                json_data = packet.http2.data_data.replace(":","")
                json_object = json.loads(codecs.decode(json_data,'hex'))
                if json_object['nfInstances'][0]['nfStatus'] =='REGISTERED':
                    # print('REGISTERED')
                    registered = True

    protocol = packet.transport_layer
    stream_id = packet.http2.streamId
    source_address = packet.ip.src
    source_port = packet[packet.transport_layer].srcport
    destination_address = packet.ip.dst
    destination_port = packet[packet.transport_layer].dstport
    packet_time = packet.sniff_time
    return {'Stream ID': stream_id, 
           'Packet Timestamp': packet_time,
           'Protocol type': protocol, 
           'Source address': source_address, 
           'Source port': source_port, 
           'Destination address': destination_address,
           'Registered' : registered, 
           'Destination port' : destination_port}

def get_http2_request_packets(packet):
    
    if hasattr(packet, 'http2') and packet[packet.transport_layer].dstport == '8006':
        results = get_packet_details(packet)

def get_http2_respond_packets(packet):
    
    if hasattr(packet, 'http2') and packet.http2.stream.find("HEADER") != -1 and packet[packet.transport_layer].srcport == '8006' and packet[packet.transport_layer].dstport == '34784': # 
        results = get_packet_details(packet)
        return results

def capture_shark(pcap_file_path):
    pkt = {}
    
    # Sniff from interface
    capture = pyshark.FileCapture(pcap_file_path, display_filter='tcp.port == 8006', decode_as={'tcp.port==8006':'http2'})  
    # packets = [pkt for pkt in capture._packets]
    # print(len(list(capture)))
    for packet in capture:
        
        results = get_http2_respond_packets(packet)
        packet_i = 'Packet_{}'.format(packet.number)
        if results is not None:
            pkt[packet_i] = results
    print(pkt)
    capture.close()
    return print('DONE')
capture_shark(pcap_file_path)