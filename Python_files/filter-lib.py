'''
    Pcap file: STOAMF1Pcap17001

'''
#Decoded for tcp.port=8006 AMF-NRF

'''Request messages'''
{'-Y': '(http2.headers.path matches "nf-instances") && (http2.headers.path matches \"requester-nf-type=AMF\") && (http2.headers.path matches \"target-nf-type=NSSF\")'}
{'-Y': '(http2.headers.path matches "nf-instances") && (http2.headers.path matches \"requester-nf-type=AMF\") && (http2.headers.path matches \"target-nf-type=AUSF\")'}
{'-Y': '(http2.headers.path matches "nf-instances") && (http2.headers.path matches \"requester-nf-type=AMF\") && (http2.headers.path matches \"target-nf-type=UDM\")'}
{'-Y': '(http2.headers.path matches "nf-instances") && (http2.headers.path matches \"requester-nf-type=AMF\") && (http2.headers.path matches \"target-nf-type=PCF\")'}
{'-Y': '(http2.headers.path matches "nf-instances") && (http2.headers.path matches \"requester-nf-type=AMF\") && (http2.headers.path matches \"target-nf-type=SMSF\")'}

'''Response messages''' 
{'-Y': '(json.member_with_value matches "nfType:NSSF") && (json.member_with_value matches "nfStatus:REGISTERED") && (http2.headers.status==200)'}
{'-Y': '(json.member_with_value matches "nfType:AUSF") && (json.member_with_value matches "nfStatus:REGISTERED") && (http2.headers.status==200)'}
{'-Y': '(json.member_with_value matches "nfType:UDM") && (json.member_with_value matches "nfStatus:REGISTERED") && (http2.headers.status==200)'}
{'-Y': '(json.member_with_value matches "nfType:PCF") && (json.member_with_value matches "nfStatus:REGISTERED") && (http2.headers.status==200)'}
{'-Y': '(json.member_with_value matches "nfType:SMSF") && (json.member_with_value matches "nfStatus:REGISTERED") && (http2.headers.status==200)'}


#Decoded for tcp.por=7000 AMF-PCF

'''Request messages'''
{'-Y': '(http2.headers.path matches "pcf") && (http2.headers.path matches "policies") && (http2.headers.method matches "POST")'} 
{'-Y': '(http2.headers.path matches "pcf") && (http2.headers.path matches "policies") && (http2.headers.method matches "DELETE")'}


'''Response messages'''
{'-Y': '(http2.headers.status==201) && (json.value.string matches "pcf") && (json.value.string matches \"imsi.*63\")'}
{'-Y': '(http2.headers.status==204) && (json.value.string matches \"imsi.*63\")'} 

#Decoded for tcp.por=5000 AMF-UDM

'''Request messages'''
{'-Y': '(http2.headers.path matches "udm") && (http2.headers.path matches "registrations")'}

'''Response messages'''
{'-Y': '(http2.headers.status==201) && (json.value.string matches "udm") && (json.value.string matches \"imsi.*63\")'}
