*** Settings ***
Documentation     Template robot main suite.
Library           http2_nf.py  

*** Variables ***
${REGISTRATION}    FALSE 


*** Tasks ***
Capture http2 packets
    
