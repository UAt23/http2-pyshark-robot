import pyshark
import json
import codecs

'''
    This function will get the packet from the captured pcap file using a Tshark filter.
It is for a specific case inside given capture file: STOAMF1Pcap17001.pcap
Filtered packet is using HTTP2 protocol with GET method to register NSSF into AMF through NRF. 

'''

pcap_file_path = "D:\WORK\python_files\STOAMF1Pcap17001.pcap"


def capture_shark(pcap_file_path):
    
    # Defining the Tshark filter parameter to pass to Pyshark function
    custom_filter_parameters = {'-Y': '(http2.headers.status==201) && (json.value.string matches "pcf") && (json.value.string matches \"imsi.*63\")'}

    # custom_filter_parameters = {"-Y": "tcp.port==8006 and http2.header.value == GET and http2.streamid==1"}
    
    
    # Packet sniff from file using Pyhsark FileCapture function
    captured_packet = pyshark.FileCapture(pcap_file_path, decode_as={'tcp.port==8006':'http2', 'tcp.port==7000':'http2', 'tcp.port==5000':'http2'}, custom_parameters=custom_filter_parameters)

    captured_packet.load_packets()
    # request = captured_packet[0].http2.headers_path
    

    return print('DONE')


capture_shark(pcap_file_path)