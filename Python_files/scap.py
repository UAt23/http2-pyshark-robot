from base64 import decode
import json
import subprocess as sp
import pprint

from json import JSONDecoder

# def parse_object_pairs(pairs):
#     return pairs     

# p1 = sp.check_output ('dir', text=True)
json_str = sp.check_output(['tshark', '-Y', 'http2.headers.path matches "target-nf-type=NSSF"', '-d', 'tcp.port==8006,http2', '-r', 'D:/WORK/robot/STOAMF1Pcap17001.pcap', '-T', 'json'], text=True)
# json_str = sp.check_output(['tshark', '-Y', 'http2.headers.path matches "target-nf-type=UDM"', '-d', 'tcp.port==8006,http2', '-r', 'D:/WORK/robot/STOAMF1Pcap17001.pcap', '-T', 'json', '-J', 'http2 json'], text=True)
# json_str = sp.check_output(['tshark', '-r', 'D:/WORK/robot/STOAMF1Pcap17001.pcap', '-Y', 'tcp.port==8006 and http2.streamid==1', \
#                     '-d', 'tcp.port==8006,http2', '-T', 'fields', '-e', 'json.member_with_value', '-e', 'json'], text=True)                                                       


# decoder = JSONDecoder(object_pairs_hook=parse_object_pairs)
# obj = decoder.decode(json_str)

tshark_pkts = json.loads(json_str)
pprint.pprint(json_str)
# Transform tshark json into a scapy-like packet-json list.
# pkts_json = [pkt['_source']['layers'] for pkt in tshark_pkts]
# pprint.pprint(pkts_json[0]['eth'])