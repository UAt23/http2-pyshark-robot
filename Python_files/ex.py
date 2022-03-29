from queue import Empty

import pyshark
import json
import codecs


pcap_file_path = "D:\WORK\python_files\STOAMF1Pcap17001.pcap"
def capture_shark(pcap_file_path):
    pkt = {}
    custom_filter_parameters = {"-Y": "tcp.port==8006 and http2.header",
                                # "-O": "http2"
                                }
    # Sniff from interface
    capture = pyshark.FileCapture(pcap_file_path, decode_as={'tcp.port==8006':'http2'}, custom_parameters=custom_filter_parameters)
    # packets = [pkt for pkt in capture._packets]
    print(len(list(capture)))
    # print(list(capture))
    # print(capture[0])
    for packet in capture:
        if hasattr(packet, 'http2') and packet.http2.stream.find("HEADER") != -1 and packet[packet.transport_layer].srcport == '8006': #


            if hasattr(packet.http2,'json_object'):
                if hasattr(packet.http2,'data_data'):
                    json_data = packet.http2.data_data.replace(":","")
                    json_object = json.loads(codecs.decode(json_data,'hex'))
                    if json_object['nfInstances'][0]['nfStatus'] =='REGISTERED':
                        # print('REGISTERED')
          
                        registered = True
                        nf_type =  json_object['nfInstances'][0]['nfType']

        packet_i = 'Packet_{}'.format(packet.number)
        pkt[packet_i] = {'Stream ID': packet.http2.streamId,
                    # 'Registered' : registered,
                    # 'NF Type' : nf_type,
                    'Packet Timestamp': packet.sniff_time,
                    'Protocol type': packet.transport_layer,
                    'Source address': packet.ip.src,
                    'Source port': packet[packet.transport_layer].srcport,
                    'Destination address': packet.ip.dst,
                    'Destination port' : packet[packet.transport_layer].dstport}

    print(pkt)
    capture.close()
    return print('DONE')


capture_shark(pcap_file_path)