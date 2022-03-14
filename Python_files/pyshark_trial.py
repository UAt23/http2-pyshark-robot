import pyshark

# Sniff from interface
cap = pyshark.FileCapture("D:\WORK\Python_files\http.cap", display_filter='http')
print(dir()))
print(cap[0])
