'''
    #Utility functions: 1) to create a packet of 1472 bytes with header (12 bytes) (sequence number, acknowledgement number,
    #flags and receiver window) and applicaton data (1460 bytes), and 2) to parse
    # the extracted header from the application data.

'''

import argparse
import ipaddress
from struct import *
from socket import *
import sys



# I integer (unsigned long) = 4bytes and H (unsigned short integer 2 bytes)
# see the struct official page for more info SARIMMSKPPPP saqiii kakkiiiii

header_format = '!IIHH'

# print the header size: total = 12
print(f'size of the header = {calcsize(header_format)}')


def create_packet(seq, ack, flags, win, data):
    # creates a packet with header information and application data
    # the input arguments are sequence number, acknowledgment number
    # flags (we only use 4 bits),  receiver window and application data
    # struct.pack returns a bytes object containing the header values
    # packed according to the header_format !IIHH
    header = pack(header_format, seq, ack, flags, win)

    # once we create a header, we add the application data to create a packet
    # of 1472 bytes
    packet = header + data
    print(f'packet containing header + data of size {len(packet)}')  # just to show the length of the packet
    return packet


def parse_header(header):
    # taks a header of 12 bytes as an argument,
    # unpacks the value based on the specified header_format
    # and return a tuple with the values
    header_from_msg = unpack(header_format, header)
    # parse_flags(flags)
    return header_from_msg


def parse_flags(flags):
    # we only parse the first 3 fields because we're not
    # using rst in our implementation
    syn = flags & (1 << 3)
    ack = flags & (1 << 2)
    fin = flags & (1 << 1)
    return syn, ack, fin


# now let's create a packet with sequence number 1
print('\n\ncreating a packet')

data = b'0' * 1460
print(f'app data for size ={len(data)}')

sequence_number = 1
acknowledgment_number = 0
window = 0  # window value should always be sent from the receiver-side
flags = 0  # we are not going to set any flags when we send a data packet

# msg now holds a packet, including our custom header and data
msg = create_packet(sequence_number, acknowledgment_number, flags, window, data)

# now let's look at the header
# we already know that the header is in the first 12 bytes

header_from_msg = msg[:12]
print(len(header_from_msg))

# now we get the header from the parse_header function
# which unpacks the values based on the header_format that
# we specified
seq, ack, flags, win = parse_header(header_from_msg)
print(f'seq={seq}, ack={ack}, flags={flags}, recevier-window={win}')

# let's extract the data_from_msg that holds
# the application data of 1460 bytes
data_from_msg = msg[12:]
print(len(data_from_msg))

# let's mimic an acknowledgment packet from the receiver-end
# now let's create a packet with acknowledgment number 1
# an acknowledgment packet from the receiver should have no data
# only the header with acknowledgment number, ack_flag=1, win=6400
data = b''
print('\n\nCreating an acknowledgment packet:')
print(f'this is an empty packet with no data ={len(data)}')

sequence_number = 0
acknowledgment_number = 1  # an ack for the last sequnce
window = 0  # window value should always be sent from the receiver-side

# let's look at the last 4 bits:  S A F R
# 0 0 0 0 represents no flags
# 0 1 0 0  ack flag set, and the decimal equivalent is 4
flags = 4

msg = create_packet(sequence_number, acknowledgment_number, flags, window, data)
print(f'this is an acknowledgment packet of header size={len(msg)}')

# let's parse the header
seq, ack, flags, win = parse_header(msg)  # it's an ack message with only the header
print(f'seq={seq}, ack={ack}, flags={flags}, receiver-window={win}')

# now let's parse the flag field
syn, ack, fin = parse_flags(flags)
print(f'syn_flag = {syn}, fin_flag={fin}, and ack_flag={ack}')











def ip_check(address):
    try:
        val= ipaddress.ip_address(address)
    except:
        print("The IP-address is in the wrong format")
        sys.exit()





def check_port(val):
    try:
        value = int(val)
    except ValueError:
        raise argparse.ArgumentTypeError('expected an integer but you entered a string')
    if (value<1024 or value>65535):
        print('it is not a valid port')
        sys.exit()





def threeWayHandshakeServer(server_socket):

    while True:
        data, address = server_socket.recvfrom(1024)

        header = data[:12]
        header_liste = parse_header(header)


        if header_liste[0] == 1:
            tom_melding = 0
            packet = create_packet(1,1,0,0,tom_melding.to_bytes(4, byteorder='big'))
            server_socket.sendto(packet, address)


            data2, address = server_socket.recvfrom(1024)

            header2 = data2[:12]
            header_liste2 = parse_header(header2)
            if header_liste2[1] == 1:
                print("Det virker")

        sys.exit()

# Method to check which reliability method is used
def checkReliability(method):

    # Checking if Stop & Wait is used
    if method == 'stopWait':
        print(f"Method is: {method}")

    # Checking if GBN is used
    elif method == 'gbn':
        print(f"Method is: {method}")

    # Checking if Selective-Repeat is used
    elif method == 'SR':
        print(f"Method is: {method}") 

    # If no method is used a simple message is printed and the server closes
    else:
        print("No method is detected, try again.")
        sys.exit()


def threeWayHandshakeClient(client_socket, address):

    data = 0
    enbytes = data.to_bytes(100, byteorder='big')
    packet = create_packet(1,0,0,0,enbytes)
    client_socket.sendto(packet, address)



    response, server_address = client_socket.recvfrom(1024)
    header = response[:12]
    header_liste = parse_header(header)


    if header_liste[0] == 1 and header_liste[1] == 1:
        ny_packet = create_packet(0,1,0,0, enbytes)

        client_socket.sendto(ny_packet,address)







#def DRTP (IP, Port):





def server(ip, port):

    #Creating a server
    sock = socket(AF_INET, SOCK_DGRAM)
    sock.bind((ip, port))


    print("[Server] server online")

    threeWayHandshakeServer(sock)

"""
    while True:
        data, address = sock.recvfrom(1024)


        message = data.decode()
        if not data:
            break
        print(message)

"""



def client(ip, port):

    # Open a UDP socket on the client
    client_socket = socket(AF_INET, SOCK_DGRAM)

    address = (ip,port)
    threeWayHandshakeClient(client_socket, address)


"""
    msg = "connected"
    client_socket.sendto(msg.encode(), address)
    """



if __name__ == '__main__':



    #Checks the argument given when trying to run the program
    #using argument parsing to take the arguments and check if they are correct

    parser = argparse.ArgumentParser()

    parser.add_argument('--server', '-s', action='store_true', help='server mode')

    parser.add_argument('--client', '-c', action='store_true', help='client mode')

    parser.add_argument('--IP', '-i', type=str, default='127.0.0.1')

    parser.add_argument('--port', '-p', type=int, default=8088)

    parser.add_argument('--reliable', '-r', type=str, required=True)

    parser.add_argument('--test_case', '-t', type=str)

    parser.add_argument('--file', '-f', type=str)





    args = parser.parse_args()


    #Will give an error when client and server both are asked to be active in one window
    if(args.server == True and args.client == True):
        print('Can´t have both server and client command')
        sys.exit()


    #server code
    elif (args.server == True ):

        #Checks some arguments to see if those are correct

        ip_check(args.IP)
        check_port(args.port)

        server(args.IP, args.port)




    #Client kode
    elif (args.client == True):

        ip_check(args.IP)
        check_port(args.port)

        client(args.IP, args.port)
