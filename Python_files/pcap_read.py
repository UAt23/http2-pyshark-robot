import pyshark
try:
    capture = pyshark.LiveCapture(interface="wlan0", output_file="pyshark.pcap")
    capture.sniff()
except KeyboardInterrupt:
    print(capture)