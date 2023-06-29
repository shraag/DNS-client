#!/usr/bin/env python
# coding: utf-8

# In[35]:

import sys
import binascii
import socket
import time

#The following function will create the message when given a hostname(url). 
#The message is first created using hex form then convert to binary form at the end and ready to send
def message(url):
    #Header Section
    ID = "aaaa"
    
    QR = "0"
    OPCODE = "{:04x}".format(0)
    AA = "0"
    TC = "0"
    RD = "1"
    RA = "0"
    Z = "{:03x}".format(0)
    RCODE = "{:04x}".format(0)

    query_parameters = "{:04x}".format(int(QR + OPCODE + AA + TC + RD +RA + Z + RCODE, 2))
    
    QDCOUNT = "{:04x}".format(1)
    ANCOUNT = "{:04x}".format(0)
    NSCOUNT = "{:04x}".format(0)
    ARCOUNT = "{:04x}".format(0)
    
    #Question Section
    url_encoded = ""
    url_sections = url.split(".")
    for section in url_sections:
        section_len = "{:02x}".format(len(section))
        section_hex = binascii.hexlify(section.encode()).decode()
        url_encoded += section_len
        url_encoded += section_hex
        
    url_encoded += "00"
    
    QTYPE = "{:04x}".format(1)
    QCLASS = "{:04x}".format(1)
    
    message_hex = ID + query_parameters + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT + url_encoded + QTYPE + QCLASS
    
    return binascii.unhexlify(message_hex)


# In[36]:


#print(message("tmz.com"))


# In[37]:


#The following function send and receive the message UDP port 53
#The received message will be a string in the hex form and ready to decode
def send_message(message, address, port = 53):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(message, (address, port))
        data, _ = sock.recvfrom(1024)
    finally:
        sock.close()
    return binascii.hexlify(data).decode("utf-8")       


# In[38]:


##initial_time = time.time() 
##Iran = send_message(message("tmz.com"), "91.245.229.1")
##ending_time = time.time() 
##elapsed_time = str(ending_time - initial_time)
##print('The Round Trip Time for {} is {}'.format('IRAN DNS resolver', elapsed_time))

##initial_time = time.time() 
##USA = send_message(message("tmz.com"), "169.237.229.88")
##ending_time = time.time() 
##elapsed_time = str(ending_time - initial_time)
##print('The Round Trip Time for {} is {}'.format('USA DNS resolver', elapsed_time))

##initial_time = time.time() 
##Canada = send_message(message("tmz.com"), "136.159.85.15")
##ending_time = time.time() 
##elapsed_time = str(ending_time - initial_time)
##print('The Round Trip Time for {} is {}'.format('Canada DNS resolver', elapsed_time))

##print("Iran Response:", Iran)
##print("USA Response:", USA)
##print("Canada Response:", Canada)


# In[39]:


#The following function is designed to decode a string in hex form bit by bit into binary form
#then concatenate into a string.
#It is only used once to parse the query parameters in the response message
def hex_to_binary(string):
    string_list = [int(x) for x in string]
    decoded = ""
    for x in string_list:
        binary_x = "{:04b}".format(x)
        decoded += binary_x
    
    return decoded


# In[44]:


#The following function will parse the entile response message and create a dictionary with all the fields
#It will only return the domain name and IP address
def response_unpack(response):
    
    #Header Section
    ID = response[0:4]
    query_parameters = response[4:8]
    QDCOUNT = response[8:12]
    ANCOUNT = response[12:16]
    NSCOUNT = response[16:20]
    ARCOUNT = response[20:24]
    query_parameters_decoded = hex_to_binary(query_parameters)
    QR = query_parameters_decoded[0:1]
    OPCODE = query_parameters_decoded[1:5]
    AA = query_parameters_decoded[5:6]
    TC = query_parameters_decoded[6:7]
    RD = query_parameters_decoded[7:8]
    RA = query_parameters_decoded[8:9]
    Z = query_parameters_decoded[9:12]
    RCODE = query_parameters_decoded[12:16]
    Header = {}
    Header.update({'ID': ID, 'QR': QR, 'OPCODE': OPCODE, 'AA': AA, 'TC': TC, 'RD': RD, 'RA': RA, 'Z': Z, 'RCODE':RCODE, 'QDCOUNT': QDCOUNT, 'ANCOUNT': ANCOUNT, 'NSCOUNT': NSCOUNT, 'ARCOUNT': ARCOUNT})
    
    #Question Section
    sections = []
    start = 24
    while int(response[start:start+2]) != 0:
        domain_len = int(response[start:start+2])
        end = start + 2 + 2*domain_len
        section = response[start+2:end]
        sections.append(section)
        start = end
    section_decoded = []
    for x in sections:
        section_decoded.append(binascii.unhexlify(x).decode())
    QNAME = '.'.join(section_decoded)
    QTYPE = response[start+2:start+6]
    QCLASS = response[start+6: start+10]
    Question = {}
    Question.update({'QNAME': QNAME, 'QTYPE': QTYPE, 'QCLASS': QCLASS})
    
    #Answer Section
    NAME = []
    TYPE = []
    CLASS = []
    TTL = []
    RDLENGTH = []
    RDDATA = []
    RDDATA_SPLIT = []
    IP_ADDRESS = []
    answer_start = start + 10
    while answer_start < len(response):
        NAME.append(response[answer_start:answer_start+4])
        TYPE.append(response[answer_start+4:answer_start+8])
        CLASS.append(response[answer_start+8:answer_start+12])
        TTL.append(int(response[answer_start+12:answer_start+20], 16))
        RDLENGTH.append(int(response[answer_start+20:answer_start+24]))
        RDDATA.append(response[answer_start+24:answer_start+24+2*RDLENGTH[-1]])
        RDDATA_split = [RDDATA[-1][i:i+2] for i in range(0, len(RDDATA[-1]), 2)]
        ip_list = []
        for i in RDDATA_split:
            j = str(int(i, 16))
            ip_list.append(j)
        ip_address = '.'.join(ip_list)
        IP_ADDRESS.append(ip_address)
        answer_start = answer_start + 24 + 2*RDLENGTH[-1]
    Answer = {}
    Answer.update({'NAME': NAME, 'TYPE': TYPE, 'CLASS': CLASS, 'TTL': TTL, 'RDLENGTH': RDLENGTH, 'RDDATA': RDDATA, 'IP ADDRESS': IP_ADDRESS})
    Whole_Response = {}
    Whole_Response.update(Header)
    Whole_Response.update(Question)
    Whole_Response.update(Answer)
    #Uncomment the following print statement if want to parse the whole response
    #print(Whole_response)
    
    if len(IP_ADDRESS) == 1:
        IP_ADDRESS = IP_ADDRESS[0]
    print("Domain:", QNAME)
    print("HTTP Server IP address:", IP_ADDRESS)


# In[45]:


##response_unpack(Iran)


# In[46]:

##response_unpack(USA)


# In[47]:


##response_unpack(Canada)


# In[49]:


###This region doesn't work (IRAN) It shows operation timed out when running
##client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
##client.connect(("10.10.34.35", 80))
##client.send(b"GET / HTTP/1.1\r\nHost:tmz.com\r\n\r\n")
##response = client.recv(4096)
##client.close()
##print(response.decode())


# In[48]:


###USA Region
##initial_time = time.time() 
##client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
##client.connect(("18.154.144.128", 80))
##client.send(b"GET / HTTP/1.1\r\nHost:tmz.com\r\n\r\n")
##response = client.recv(4096)
##client.close()
##print(response.decode())
##ending_time = time.time() 
##elapsed_time = str(ending_time - initial_time)
##print('The Round Trip Time for TCP connection of {} server is {}'.format('USA', elapsed_time))
##

# In[50]:


###Canada Region
##initial_time = time.time() 
##client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
##client.connect(("18.65.229.23", 80))
##client.send(b"GET / HTTP/1.1\r\nHost:tmz.com\r\n\r\n")
##response = client.recv(4096)
##client.close()
##print(response.decode())
##ending_time = time.time() 
##elapsed_time = str(ending_time - initial_time)
##print('The Round Trip Time for TCP connection of {} server is {}'.format('Canada', elapsed_time))

if __name__ == '__main__':
    args = sys.argv[1]
    response = send_message(message(args), "169.237.229.88")
    response_unpack(response)
