*** Settings ***
Documentation     Template robot main suite.
Library           nf_instances.py

***Variables***
${PATH}           D://WORK//python_files//STOAMF1Pcap17001.pcap

*** Tasks ***
Check the url
    ${url_path}    CAPTURE SHARK    ${PATH}
    
    ${contains}=    Run Keyword And Return Status    Should Contain    ${source}    is a

