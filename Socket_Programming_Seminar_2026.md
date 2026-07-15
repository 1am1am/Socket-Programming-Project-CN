**SOCKET PROGRAMMING** *Internetworking Protocols* 

Lecturer: Chung Thùy Linh · ctlinh@fit.hcmus.edu.vn 

FIT · HCMUS  
**Table of Contents** 

*Agenda* 

**01** OSI & TCP/IP Model · TCP vs UDP 

**02** TCP Header · UDP Header · FTP Header **03** Flow Control · Congestion Control · Ordering & Loss **04** Socket Introduction · Building a Client–Server App **05** Python socket – Core Functions 

**06** FTP Protocol – How It Works 

**07** Demo: TCP Chat · UDP Chat (Python)  
**OSI & TCP/IP Model** 

*Layered Network Architecture* 

**Layer OSI Model TCP/IP Model 7 Application** 

**Socket at Transport Layer** 

**Socket ID:** IP \+ Port \+ Protocol 

**6 Presentation 5 Session 4 Transport 3 Network 2 Data Link 1 Physical**   
**Applications** 

**(FTP, HTTP, SMTP…)** 

**TCP / UDP** 

**(host-to-host)** 

**IP** 

**Network Access (Ethernet, WiFi)** 

**Source IP:** Sender's IP address **Dest IP:** Receiver's IP address **Source MAC:** Sender NIC address **Dest MAC:** Receiver NIC address  
**TCP vs UDP – Comparison** 

*Transport Layer Protocols* 

**TCP – Transmission Control Protocol UDP – User Datagram Protocol** 

**Connection** Connection-oriented (3-way handshake)   
Connectionless (No setup required) 

**Reliability** Guaranteed delivery (Reliable) No guarantee (Best-effort) 

**Ordering** Ordered packet delivery No ordering guarantee 

**Speed** Slower (due to overhead) Faster (minimal overhead) 

**Control** Flow \+ Congestion Control None 

**Cast type** Unicast only Unicast, Multicast, Broadcast 

**Use cases** HTTP/S, Email, FTP, SSH VoIP, DNS, Video Streaming, Gaming ![][image1]Reliable ![][image2]Ordered ![][image3]Congestion Control ![][image4]High Speed ![][image5]Real-time Friendly ![][image6]Multicast/Broadcast  
**TCP Header – Packet Structure** 

*Minimum 20 bytes · Transport Layer* 

0 15 16 31 

**Source Port (16 bits)** 16 bits **Destination Port (16 bits)** 16 bits **Sequence Number (32 bits)** 32 bits **Acknowledgment Number (32 bits)** 32 bits **Data Offset | Reserved | Control Flags** 16 bits **Window Size (16 bits)** 16 bits **Checksum (16 bits)** 16 bits **Urgent Pointer (16 bits)** 16 bits Options (0–40 bytes, variable) var bits Data / Payload 

*Control Flags: URG · ACK · PSH · RST · SYN · FIN (1 bit each)*  
**UDP Header – Packet Structure** 

*Fixed 8 bytes · Simple & Fast* 

**Source Port (16 bits)** 

Source port number (optional, \= 0 if not used) 

**Destination Port (16 bits)** 

Destination port number 

**Length (16 bits)** 

Total length of UDP header \+ data (in bytes) 

**Checksum (16 bits)** 

Error-checking (optional in IPv4, mandatory in IPv6) 

**Data / Payload** 

Application data 

UDP header is only 8 bytes (vs TCP's minimum 20 bytes). No sequence numbers, ACK or flow control → faster but unreliable. Best for: VoIP,  DNS, video streaming, gaming.  
**TCP – Connection Establishment (3-Way Handshake)** *SYN · SYN-ACK · ACK* 

**CLIENT SERVER** 

**①SYN (SEQ=100, CTL=SYN)** 

*Step 1: Client requests connection* 

**②SYN+ACK (SEQ=300, ACK=101)** 

*Step 2: Server acknowledges \+ sends SYN* 

**③ACK (SEQ=101, ACK=301)** 

*Step 3: Client confirms → Connection ESTABLISHED* 

**ESTABLISHED ![][image7]ESTABLISHED ![][image8]** *CTL \= Control bits in TCP header; ACK number \= next expected byte from receiver*  
**TCP – Flow Control** 

*Preventing receiver buffer overflow* 

**How It Works** 

**1 Receive Window (rwnd)** 

Receiver advertises remaining buffer space in every ACK 

**2 Sender adjusts** 

Sender must not have more than rwnd unacknowledged bytes in  flight 

**3 Window \= 0** 

Sender pauses; waits for receiver to announce new window 

**4 Sliding Window** 

Window 'slides' forward with each ACK received 

**Sliding Window – Illustration** 

**1 2 3 4 5 6 7 8 9 10** 

Sent & ACK'd 

Sent, awaiting ACK (in window) 

Not yet sent 

**Send Condition:**   
**LastByteSent – LastByteAcked ≤ rwnd** 

*Window size is 16 bits → max 65,535 bytes; use Window Scale Option (RFC  1323\) to extend*  
**TCP – Congestion Control** *Preventing network congestion* 

**Slow Start** 

cwnd starts at 1 MSS Doubles every RTT until reaching ssthresh   
**Congestion Avoidance** 

cwnd increases linearly (+1 MSS/RTT) 

when cwnd ≥ ssthresh   
**Fast Retransmit** 

3 duplicate ACKs → retransmit lost packet immediately (no timeout)   
**Fast Recovery** 

ssthresh \= cwnd/2   
cwnd \= ssthresh 

Resume Congestion Avoidance  
**TCP – Packet Ordering & Loss Recovery** *Sequence Numbers · Retransmission · ARQ* 

**Packet Ordering** 

**1\.** Each TCP segment carries a Sequence Number (SEQ) identifying the first  byte of its payload. 

**2\.** Receiver uses SEQ to reorder out-of-order segments into the correct  sequence. 

**3\.** Early-arriving segments are buffered until the missing segment arrives. **4\.** Receiver sends ACK \= SEQ of the next expected byte (Cumulative ACK). 

**5\.** Once buffer is complete and ordered, data is passed up to the  application layer.   
**Loss Detection & Recovery** 

**Timeout (RTO)** 

Sender starts a timer; if it expires before ACK arrives → retransmit all  segments from the lost one. 

**3 Duplicate ACKs (Fast Retransmit)** 

On 3 duplicate ACKs → immediately retransmit without waiting for timeout. 

**Selective ACK (SACK)** 

Extension allowing receiver to report exactly which segments arrived,  avoiding redundant retransmissions. 

**Go-Back-N vs Selective Repeat** 

TCP uses a variant of Selective Repeat to optimize network performance.  
**Socket Introduction** 

*Socket Programming · Winsock API · POSIX* 

 **What is a Socket?** 

An end-point of a communication link between two networked  applications. It provides an interface for network programming at  the Transport layer. 

 **Winsock API** 

Windows Socket API – supports building TCP/IP network  applications on Windows. MFC provides the CSocket class as a  wrapper. 

 **Socket Identity** 

A socket is uniquely identified by: IP Address \+ Port Number \+  Protocol (TCP/UDP) 

 **Languages & Platforms** 

C, C++, Java, Python, C\#, VB, ... Cross-platform: Windows  (Winsock), Linux/macOS (POSIX sockets)  
**Building a Client–Server Application** 

*TCP Socket Workflow* 

**SERVER CLIENT** 

**Create(port)** 

Create socket & register port 

**Listen()** 

Listen for incoming connections 

**Accept(s)** 

Accept one connection 

**Send() / Receive()** Send / Receive data 

**Close()** 

Close connection 

connect data ⇄  
**Create()** 

Create socket (no port needed) 

**Connect(IP, port)** Connect to server 

**Send() / Receive()** Send / Receive data 

**Close()** 

Close connection   
**Python – socket Library** 

*import socket · Cross-platform: Windows / Linux / macOS* 

**TCP Server TCP Client** 

import socket 

s \= socket.socket( 

 socket.AF\_INET,  socket.SOCK\_STREAM) s.bind(('0.0.0.0', 1234)) s.listen(5)   
conn, addr \= s.accept() data \= conn.recv(1024) conn.send(b'Hello\!') conn.close() 

s.close()   
import socket 

c \= socket.socket( 

 socket.AF\_INET, 

 socket.SOCK\_STREAM) 

c.connect(('127.0.0.1', 1234)) 

c.send(b'Hello Server\!')   
data \= c.recv(1024) 

print(data.decode()) 

c.close() 

**Key functions in the socket module** 

**socket(AF\_INET, SOCK\_STREAM|SOCK\_DGRAM) create** Create a TCP (STREAM) or UDP (DGRAM) socket **bind((host, port)) server** Bind socket to a specific IP address and port **listen(backlog) server** Start listening; backlog \= max pending connection queue **accept() server** Block and wait for a client → returns (conn\_socket, addr) **connect((host, port)) client** Client connects to server at host:port **send(data) / recv(size) TCP** Send/receive bytes over an established TCP connection **sendto(data, addr) / recvfrom(size) UDP** Send/receive UDP datagrams (no connect required) **close() close** Close socket and release resources  
**Demo – TCP Chat Application (1 Server – 1 Client)** *Sequential chat: Server sends first* 

**Scenario:** Server sends → Client receives & replies → Server receives & replies → ... (loop until either side types 'exit'). Message format:  \<length\>\<message\> 

**SERVER (afxsock.h) CLIENT (afxsock.h)** 

CSocket server, s;   
AfxSocketInit(NULL);   
server.Create(1234); 

server.Listen();   
server.Accept(s);   
do {   
 printf("\\nServer: ");   
 gets(s\_str); len=strlen(s\_str);  s.Send(s\_str, len, 0); 

 len \= s.Receive(r\_str,100,0);  r\_str\[len\] \= 0; 

 printf("\\nClient: %s", r\_str); } while(strcmp(r\_str,"exit") &&  strcmp(s\_str,"exit")); s.Close(); server.Close();   
CSocket client;   
AfxSocketInit(NULL);   
client.Create(); 

client.Connect(svrAddr, 1234); do { 

 len=client.Receive(r\_str,100,0);  r\_str\[len\] \= 0; 

 printf("\\nServer: %s", r\_str);  printf("\\nClient: "); 

 gets(s\_str);   
 client.Send(s\_str,   
 strlen(s\_str), 0); } while(strcmp(r\_str,"exit") &&  strcmp(s\_str,"exit")); client.Close(); 

Server calls Create(port) to register port; Client calls Create() with no port then Connect(IP, port)  
**Demo – UDP Chat Application (Python)** 

*Connectionless · socket.SOCK\_DGRAM · sendto / recvfrom* 

**Scenario:** Server binds to a port and waits. Client sends a datagram, server receives it with recvfrom() (learns client address), replies with  sendto(). Loop until either side sends 'exit'. No handshake required. 

**UDP SERVER (Python) UDP CLIENT (Python)** 

import socket 

s \= socket.socket( 

 socket.AF\_INET,   
 socket.SOCK\_DGRAM)   
s.bind(('0.0.0.0', 1234))   
print("UDP Server ready...") 

while True: 

 data, addr \= s.recvfrom(1024)  msg \= data.decode() 

 print(f"Client: {msg}")  if msg \== 'exit': break  reply \= input("Server: ")  s.sendto(reply.encode(), addr)  if reply \== 'exit': break 

s.close()   
import socket 

c \= socket.socket( 

 socket.AF\_INET,   
 socket.SOCK\_DGRAM)   
srv \= ('127.0.0.1', 1234\) 

while True:   
 msg \= input("Client: ")  c.sendto(msg.encode(), srv)  if msg \== 'exit': break  data, \_ \= c.recvfrom(1024)  reply \= data.decode()  print(f"Server: {reply}")  if reply \== 'exit': break 

c.close() 

**Key differences vs TCP: No listen()/accept() · Use SOCK\_DGRAM · sendto(data, addr) & recvfrom(size) · No FIN on close**  
**Demo – TCP chat vs UDP chat** 

**TCP Chat vs UDP Chat – Comparison:** 

**Feature TCP UDP** 

**Connection setup** socket() → bind() → listen() → accept() socket() → bind() (server) socket() (client only) 

**Sending data** send(socket, data, len, 0\) sendto(socket, data, len, 0, addr, addrLen) **Receiving data** recv(socket, buf, len, 0\) recvfrom(socket, buf, len, 0, addr, \&addrLen) **Termination** close(socket) \[FIN exchange\] close(socket) \[no FIN needed\] **Reliability** Guaranteed delivery ✘ Best-effort, packets may be lost **Best for** FTP, HTTP, Email, SSH VoIP, DNS, Video streaming, Gaming  
**FTP – Active Mode vs Passive Mode** *Connection diagram: Control & Data channels · RFC 959* **ACTIVE MODE** 

**PASSIVE MODE (PASV)** 

**CLIENT** 10.0.0.1   
**SERVER** 10.0.0.2   
**CLIENT** 10.0.0.1   
**SERVER** 10.0.0.2 

**port P port 21** 

**① Control connection (client → port 21\)** 

**port Q** 

②Client opens port Q, sends PORT Q   
 command to notify server 

**port Q port 20** 

**③Server initiates Data connection**   
 **(port 20 → client port Q)** 

Problem: Server initiates inbound connection to client → Firewall/NAT on client  side typically blocks this → client must open port Q   
**port P port 21** 

**① Control connection (client → port 21\)** 

**port R** 

②Client sends PASV → Server opens random   
 port R, replies with R to client 

**port Q port R** 

**③Client initiates Data connection**   
 **(→ server port R)** 

Advantage: Client always initiates outbound connections → Firewall/NAT on client  side does not block. Ideal for modern internet environments.  
**FTP – File Transfer Protocol Header** *Application Layer · Port 20 (data) & Port 21 (control)* 

**FTP Commands (Control Channel)** 

*Port 21 · Control channel* 

**USER \<username\>** Send login username **PASS \<password\>** Send password **LIST** List files/directories **RETR \<filename\>** Download file from server **STOR \<filename\>** Upload file to server **PASV** Switch to Passive mode **QUIT** Terminate FTP session   
**FTP Response Codes** 

*3-digit code \+ descriptive message* 

**1xx** Positive Preliminary (in progress) **2xx** Positive Completion (success) **3xx** Positive Intermediate (more info needed) **4xx** Transient Negative (temporary error) **5xx** Permanent Negative (fatal error) **220** Service ready for new user 

**230** User logged in successfully 

**226** Closing data connection, transfer OK **550** File unavailable or access denied  
**Summary** 

▸ OSI 7 layers & TCP/IP 4 layers – Socket operates at Transport layer ▸ TCP vs UDP – Reliability vs Speed; choose based on application needs ▸ TCP Header (20B) · UDP Header (8B) · FTP Command / Response codes ▸ Flow Control (rwnd) · Congestion Control (cwnd, ssthresh) 

▸ Sequence Numbers · Timeout · Fast Retransmit · SACK 

▸ Python socket API: socket() → bind() → listen() → accept() → send/recv → close() 

▸ FTP: Active Mode (ports 20/21) vs Passive Mode (PASV) — firewall implications FIT · HCMUS · ctlinh@fit.hcmus.edu.vn

[image1]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABcAAAAYCAYAAAARfGZ1AAAArElEQVR4Xu2QLw7CMBhHx59kyDlAE07ARXBTOBQSEjzn4RJYFAmWcIaayjbl/RIwn2JNptaXvHRLv71uq6rCsEkpzWSM8cK6xZG0c1n0Gg8hnCTBJ27sfjbE1rzxXXLAmfupnfkbHq6xwcnX4y/unGvsfCd6jfPpLaEX604S1+/YSzvbGWJz4lfWt+T6wbqSdjYL7/2C6E0SPeBY2rkseo0LDlhKorXdKxSGzgfjLtlM+EUjngAAAABJRU5ErkJggg==>

[image2]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABcAAAAYCAYAAAARfGZ1AAAArElEQVR4Xu2QLw7CMBhHx59kyDlAE07ARXBTOBQSEjzn4RJYFAmWcIaayjbl/RIwn2JNptaXvHRLv71uq6rCsEkpzWSM8cK6xZG0c1n0Gg8hnCTBJ27sfjbE1rzxXXLAmfupnfkbHq6xwcnX4y/unGvsfCd6jfPpLaEX604S1+/YSzvbGWJz4lfWt+T6wbqSdjYL7/2C6E0SPeBY2rkseo0LDlhKorXdKxSGzgfjLtlM+EUjngAAAABJRU5ErkJggg==>

[image3]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABcAAAAYCAYAAAARfGZ1AAAArElEQVR4Xu2QLw7CMBhHx59kyDlAE07ARXBTOBQSEjzn4RJYFAmWcIaayjbl/RIwn2JNptaXvHRLv71uq6rCsEkpzWSM8cK6xZG0c1n0Gg8hnCTBJ27sfjbE1rzxXXLAmfupnfkbHq6xwcnX4y/unGvsfCd6jfPpLaEX604S1+/YSzvbGWJz4lfWt+T6wbqSdjYL7/2C6E0SPeBY2rkseo0LDlhKorXdKxSGzgfjLtlM+EUjngAAAABJRU5ErkJggg==>

[image4]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABwAAAAYCAYAAADpnJ2CAAABMUlEQVR4XmNgGAWDCHADsSAUM6LJUR3wGqlzz5GXZJsJwkA+H7oCagGQwXw2+jw908qUfuoocdSBMFCMBV0htQD9LJQVZpCK9RCZD8JnFhj87MtXvAcUtoNiqgOBKDeRBSfm6f0G4T/HbP5baPM+B4pPgeIWKA4BYjYoJhuIuFvwzwT56sch6/8g/OuI9X8gH45PzNX/35Et/0tJmr0HqJ4TiskG9LVQkI/BPTtE4uisCpWzsytVwbi/QOne+UWG/38ftQbjnRO0fxmq84CCVgxdPzmAC4hVgVgLCc+6tNTo/7Z+bTB2MeVfCBQTQdZELQAyVMTbSvDw2jaNb1Z6PJNBmIeBQRRdIbUA3S10BOFAB6EH+irc3QwQi2hmGQjogLAQH1MukOZHlxwFo2AUkAUAMV+GiHWs6zsAAAAASUVORK5CYII=>

[image5]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABwAAAAYCAYAAADpnJ2CAAABMUlEQVR4XmNgGAWDCHADsSAUM6LJUR3wGqlzz5GXZJsJwkA+H7oCagGQwXw2+jw908qUfuoocdSBMFCMBV0htQD9LJQVZpCK9RCZD8JnFhj87MtXvAcUtoNiqgOBKDeRBSfm6f0G4T/HbP5baPM+B4pPgeIWKA4BYjYoJhuIuFvwzwT56sch6/8g/OuI9X8gH45PzNX/35Et/0tJmr0HqJ4TiskG9LVQkI/BPTtE4uisCpWzsytVwbi/QOne+UWG/38ftQbjnRO0fxmq84CCVgxdPzmAC4hVgVgLCc+6tNTo/7Z+bTB2MeVfCBQTQdZELQAyVMTbSvDw2jaNb1Z6PJNBmIeBQRRdIbUA3S10BOFAB6EH+irc3QwQi2hmGQjogLAQH1MukOZHlxwFo2AUkAUAMV+GiHWs6zsAAAAASUVORK5CYII=>

[image6]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABwAAAAYCAYAAADpnJ2CAAABMUlEQVR4XmNgGAWDCHADsSAUM6LJUR3wGqlzz5GXZJsJwkA+H7oCagGQwXw2+jw908qUfuoocdSBMFCMBV0htQD9LJQVZpCK9RCZD8JnFhj87MtXvAcUtoNiqgOBKDeRBSfm6f0G4T/HbP5baPM+B4pPgeIWKA4BYjYoJhuIuFvwzwT56sch6/8g/OuI9X8gH45PzNX/35Et/0tJmr0HqJ4TiskG9LVQkI/BPTtE4uisCpWzsytVwbi/QOne+UWG/38ftQbjnRO0fxmq84CCVgxdPzmAC4hVgVgLCc+6tNTo/7Z+bTB2MeVfCBQTQdZELQAyVMTbSvDw2jaNb1Z6PJNBmIeBQRRdIbUA3S10BOFAB6EH+irc3QwQi2hmGQjogLAQH1MukOZHlxwFo2AUkAUAMV+GiHWs6zsAAAAASUVORK5CYII=>

[image7]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABsAAAAdCAYAAABbjRdIAAAA2ElEQVR4Xu2UMQrCMBSGraCLg4OD6AkUBC/h5iR4Ah3Uk7g4uvQansFN3BxET+DsIG1T4vcgILyxCQUhH3wk0Mf/Q0LaaEQikapYa9vORNTfg5Bl2UQsyzLFPUV9Uc95Q+gQT84cU+yKetab2soIbOKKo3uL7G841XNBIHhAyYPVODd6pjKEzY0xO5H9mHUtJRQ+xaBHV2sZgUcC5W7kjs6sd/xQuhVtyLdFWI+Sq2h/XHAk6nlfkqIoliLhL8wpPlj359DD3hDacs5wgR09E4xayyKRyH/wBfgaKdQ7Cs6uAAAAAElFTkSuQmCC>

[image8]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABsAAAAdCAYAAABbjRdIAAAA2ElEQVR4Xu2UMQrCMBSGraCLg4OD6AkUBC/h5iR4Ah3Uk7g4uvQansFN3BxET+DsIG1T4vcgILyxCQUhH3wk0Mf/Q0LaaEQikapYa9vORNTfg5Bl2UQsyzLFPUV9Uc95Q+gQT84cU+yKetab2soIbOKKo3uL7G841XNBIHhAyYPVODd6pjKEzY0xO5H9mHUtJRQ+xaBHV2sZgUcC5W7kjs6sd/xQuhVtyLdFWI+Sq2h/XHAk6nlfkqIoliLhL8wpPlj359DD3hDacs5wgR09E4xayyKRyH/wBfgaKdQ7Cs6uAAAAAElFTkSuQmCC>