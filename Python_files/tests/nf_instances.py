import pyshark
import json
import codecs

streamid = 1
pcap_file_path = "D:\WORK\python_files\STOAMF1Pcap17001.pcap"
def capture_shark(pcap_file_path, streamid):
    custom_filter_parameters = {"-Y": "tcp.port==8006 and http2.header and http2.streamid=={}".format(streamid),
                                # "-O": "http2"
                                }
    # Sniff from interface
    capture = pyshark.FileCapture(pcap_file_path, decode_as={'tcp.port==8006':'http2'}, custom_parameters=custom_filter_parameters)
    print(len(list(capture)))
    capture.load_packets()
    request = capture[0].http2.headers_method
    response = capture[1].http2.data_data
    json_object = json.loads(codecs.decode(response.replace(":",""),'hex'))
    registered = json_object['nfInstances'][0]['nfStatus']
    nf_type =  json_object['nfInstances'][0]['nfType']

    
    return print('DONE')


# capture_shark(pcap_file_path, streamid)