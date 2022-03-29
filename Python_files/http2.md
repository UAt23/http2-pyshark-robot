http2 standard: https://www.rfc-editor.org/rfc/rfc7540#section-3.1 

STEPS:

    -The first step of establishing a TLS connection is to exchange what are called “hello messages” that allow the client and server to “agree on algorithms, exchange random values, and check for session resumption”. With ALPN, the client sends a list of supported protocols to the server as part of the client’s hello message, and the server selects a protocol from this list and sends it back to the client as part of the server’s hello message.

    -In addition to agreeing on h2 is the protocol for the TLS connection, the client and the server must send a pre-defined “connection preface” as a final confirmation of the protocol, and to establish any initial settings for the h2 connection. The client begins by sending the string PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n as the first data of the TLS connection. The client must follow this string with an h2 SETTINGS frame. The server responds with a SETTINGS frame. From this point forward, a valid HTTP/2 connection is established. 

    -The Magic is a not a frame but a special set of bytes, resembling an HTTP/1.1 message. It is sent at the beginning of all HTTP/2 connections to allow HTTP/1.1 servers to reject the connection elegantly with an HTTP/1.1 response so the client knows to revert back to HTTP/1.1.

    -In summary, establishing an HTTP/2 connection requires:

        ~Establishing a TLS connection
        ~Negotiating h2 as the protocol for the TLS extension using ALPN
        ~The client sending (and server receiving) an h2 connection preface and SETTINGS frame
        ~The server sending (and client receiving) an h2 SETTINGS frame.


        -An HTTP request/response exchange fully consumes a single stream. An HTTP response is complete after the server sends – or the client receives – a frame with the END_STREAM flag set. This closes the stream, and any additional HTTP request/response exchanges take place on a new stream. This new stream shares the same TCP/IP connection.

Frames:

    SETTINGS:
        
        - A SETTINGS frame MUST be sent by both endpoints at the start of a
        connection and MAY be sent at any other time by either endpoint over
        the lifetime of the connection.  Implementations MUST support all of
        the parameters defined by this specification.
        
        - SETTINGS frames always apply to a connection, never a single stream.
        The stream identifier for a SETTINGS frame MUST be zero (0x0).  If an
        endpoint receives a SETTINGS frame whose stream identifier field is
        anything other than 0x0, the endpoint MUST respond with a connection
        error of type PROTOCOL_ERROR.
    
    GO_AWAY:

        - The GOAWAY frame (type=0x7) is used to initiate shutdown of a connection or to signal serious error conditions. GOAWAY allows an endpoint to gracefully stop accepting new streams while still finishing processing of previously established streams. This enables administrative actions, like server maintenance.


Flow Control:

    - Flow control is based on WINDOW_UPDATE frames.  Receivers
    advertise how many octets they are prepared to receive on a
    stream and for the entire connection.  This is a credit-based
    scheme.

    - The frame type determines whether flow control applies to a
    frame.  Of the frames specified in this document, only DATA
    frames are subject to flow control; all other frame types do not
    consume space in the advertised flow-control window.  This
    ensures that important control frames are not blocked by flow
    control.

 ./tshark.exe  -R "http2" -Y http2.header.value -d tcp.port==8006,http2 -r D:/WORK/robot/STOAMF1Pcap17001.pcap -2