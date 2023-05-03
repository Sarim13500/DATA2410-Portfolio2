'''
    #Utility functions: 1) to create a packet of 1472 bytes with header (12 bytes) (sequence number, acknowledgement number,
    #flags and receiver window) and applicaton data (1460 bytes), and 2) to parse
    # the extracted header from the application data.

'''

import argparse
import ipaddress
import time
from struct import *
from socket import *
import sys



# I integer (unsigned long) = 4bytes and H (unsigned short integer 2 bytes)
# see the struct official page for more info

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



def ip_check(address):
    # Her så sjekker vi ip adressen, hvis ip er feil så sender vi ut en feilmelding
    try:
        val= ipaddress.ip_address(address)
    except:
        print("The IP-address is in the wrong format")
        sys.exit()



def check_port(val):
    # Her sjekker vi porten, hvis porten er feil så sender vi ut en feilmelding
    try:
        value = int(val)
    except ValueError:
        raise argparse.ArgumentTypeError('expected an integer but you entered a string')
    # If setning for å sjekke at porten er innenfor gitt verdi
    if (value<1024 or value>65535):
        print('it is not a valid port')
        sys.exit()






# Denne koden implementerer en three-way-handshake protokoll på ved hjelp av UDP-tilkobling.
# Protokollen sørger for å etablere en pålitelig forbindelse mellom klient og server.
# Hvis protokollen fullføres vellykket, vil metoden skrive ut. Hvis protokollen mislykkes,
# vil metoden avslutte programmet
def threeWayHandshakeServer(server_socket):

    while True:
        # Mottar data fra klienten ved bruk av UDP-tilkobling, og lagrer dataene i variabler
        data, address = server_socket.recvfrom(2000)

        # Henter de første 12 bytene av mottatt data og
        # parser headeren for å konvertere den til en liste
        header = data[:12]
        header_liste = parse_header(header)



        # Hvis den første verdien i header-listen er lik 1,lager vi en tom pakke ved bruk av "create_packet" funksjonen
        # og sender pakken til klienten ved hjelp av UDP.
        # Serveren sender en bekreftelsespakke tilbake til klienten for å signalisere at den er klar for å motta data
        if header_liste[0] == 1:
            tom_melding = 0
            packet = create_packet(1,1,0,0,tom_melding.to_bytes(4, byteorder='big'))
            server_socket.sendto(packet, address)



            # Her mottar vi data fra klienten ved hjelp av UDP-tilkobling,
            # og parser deretter headeren til mottatt data.
            data2, address = server_socket.recvfrom(2000)

            header2 = data2[:12]
            header_liste2 = parse_header(header2)
            # Hvis den andre verdien i header-listen er lik 1, så har klienten mottatt serverens bekreftelsespakke
            # og er klar for å fullføre protokollen. Printer ut melding og avslutter programmet
            if header_liste2[1] != 1:
                print("Det var en feil. start på nytt")
                sys.exit()
        break




# Her så vi implementerer treveis håndhilsen protokollen for en klient ved å
# sende en pakke til serveren og vente på en bekreftelsespakke før den sender en ny pakke til
# serveren for å fullføre protokollen.

def threeWayHandshakeClient(client_socket, address):
    # Her så vi sender en pakke til serveren med data i byte-format ved å
    # konvertere dataverdien til bytes og sender pakken til serveren ved hjelp av UDP-tilkobling.
    data = 0
    enbytes = data.to_bytes(100, byteorder='big')
    packet = create_packet(1,0,0,0,enbytes)
    client_socket.sendto(packet, address)



    # Her så mottar vi en respons fra serveren og henter ut header-delen av responsen,
    # deretter konverterer headeren til en liste ved hjelp av en funksjon kalt parse_header().
    response, server_address = client_socket.recvfrom(2000)
    header = response[:12]
    header_liste = parse_header(header)


    # Koden sjekker headeren i responsen fra serveren for å bekrefte at den mottok riktig packets med riktig flagg,
    # og deretter sender en ny pakke med data til serveren for å fullføre three-way-handshake protokollen.
    if header_liste[0] == 1 and header_liste[1] == 1:
        ny_packet = create_packet(0,1,0,0, enbytes)

        client_socket.sendto(ny_packet,address)


# Her så Sender vi filen til serveren ved hjelp av stop-and-wait protokollen.
# Leser filen bit for bit og sender hvert segment til serveren før den venter på en ACK-melding.
# Hvis ACK-meldingen er mottatt, sender den neste biten av filen, og så videre.
# Dersom det ikke mottas noen ACK-melding etter en viss tid, sender den samme biten igjen.
# Til slutt sender den en avslutningsmelding til serveren når hele filen er sendt.

def stop_and_wait_client(client_socket, addresse, fil, test_case):

    # Oppretter variabler for videre bruk
    packet_str = 1460
    packets = {}
    packet_num = 1
    kjor = 1
    ack_num = 0


    with open(fil, 'rb') as file:

        while kjor==1:

            data = file.read(packet_str)

            if test_case == "loss" and packet_num ==1:
                packet_num += 1

            packet_name = f'packet{packet_num}'
            packets[packet_name] = create_packet(packet_num,0,0,0,data)
            client_socket.sendto(packets[f'packet{packet_num}'], addresse)


            svar, addresse = client_socket.recvfrom(2000)

            header = svar[:12]

            header_liste = parse_header(header)


            try:
                client_socket.settimeout(0.5)

                if header_liste[1] == packet_num:
                    ack_num += 1
                    packet_num += 1
                else:
                    break


            except timeout:
                packet_num += 1

            if not data:
                finished_packet = create_packet(0,0,1,0, "".encode("utf-8"))
                client_socket.sendto(finished_packet, addresse)
                kjor=0





def stop_and_wait_server(server_socket, test_case):

    kjor =1
    packet_nmr = 0
    ack =1

    while kjor==1:
        packet, addresse = server_socket.recvfrom(2000)

        header = packet[:12]

        header = parse_header(header)

        if header[2] == 1:
            print("[SERVER] Finished")
            print("[SERVER] closing...")
            time.sleep(1)
            print("[SERVER] closed")
            break

        tom = ""

        if packet_nmr+1 == header[0]:
            packet_nmr += 1

            if test_case != "skip_ack":
                send_packet = create_packet(0,ack,0,0,tom.encode('utf-8'))
                server_socket.sendto(send_packet,addresse)
            ack +=1

        elif packet_nmr == header[0]:
            kjor = 0
            break

        else:
            send_packet = create_packet(0, 0, 0, 0, packet)
            server_socket.sendto(send_packet, addresse)




def gbn_client(client_socket, address, file, test_case):
    # Oppretter variabler for videre bruk
    packet_size = 1460  # Maks str på pakkeinnhold
    packets = {}  # Array for å lagre pakker som skal bli sendt
    packet_num = 1  # SekvensNr til neste pakke som skal sendes
    window_size = 5  # Størrelse til senderens vindu
    ack_num = 0  # SekvensNr til den siste pakken som ble bekreftet av mottakeren
    base = 1  # SekvensNr til den eldste ubekfreftet pakken
    packets_sent = False  # Variabel som indikerer om alle pakkene har blitt sendt

    # Åpner filen som skal sendes
    with open(file, 'rb') as file:

        # Kjører en while-løkke så lenge alle pakkene har blitt sendt og bekreftet
        while not packets_sent:

            # Sender pakker i senderes window_size
            for i in range(base, min(base + window_size, packet_num + 1)):
                if i not in packets:
                    # Leser data fra filen og lager en pakke
                    data = file.read(packet_size)

                    if not data:
                        # All data-en har blitt lest fra filen
                        packets_sent = True
                        break
                    packet_name = f'packet{i}'
                    packets[packet_name] = create_packet(i, 0, 0, 0, data)


                # Sender pakkene
                client_socket.sendto(packets[f'packet{i}'], address)


            # Venter på bekreftelse fra mottakeren
            try:
                client_socket.settimeout(0.5)
                while True:
                    response, _ = client_socket.recvfrom(2000)
                    header = response[:12]
                    header_list = parse_header(header)
                    # Hvis bekreftelsen er for den neste forventede pakken
                    if header_list[1] == base:
                        ack_num = header_list[1]
                        base += 1
                    # Hvis bekreftelsen er for en pakke i senderes vindu
                    elif header_list[1] > base:
                        base = header_list[1]
                    # Hvis alle pakker har blitt bekreftet
                    if base > packet_num:
                        packets_sent = True
                        break
            # Hvis avsenderen går tom for tid mens den venter på en bekreftelse
            except timeout:
                pass

        finished_packet = create_packet(0, 0, 1, 0, "".encode("utf-8"))
        client_socket.sendto(finished_packet, address)







def gbn_server(server_socket, test_case):
    # Oppretter variabeler for videre bruk
    packet_size = 1460
    packet_num = 1
    ack = 1
    base = 1
    kjor = True
    packets = {}

    while kjor:
        # Mottar pakke fra klient
        packet, address = server_socket.recvfrom(2000)

        # Parser pakke header
        header = packet[:12]
        header_list = parse_header(header)

        # Hvis pakkeNr er som forventet, sender i en ACK  og lagrer pakken
        if header_list[0] == packet_num:
            # Trekker ut data fra pakken og lagrer pakken i arrayet
            data = packet[12:]
            packet_name = f'packet{packet_num}'
            packets[packet_name] = packet

            # Sender en ACK med de forventende ACK NR
            if test_case != "skip_ack":
                server_socket.sendto(create_packet(packet_num, ack, 0, 0, "".encode('utf-8')), address)

            # Oppdaterer forventende pakke og ACK number
            packet_num += 1
            ack += 1

        # Hvis pakkeNR er mindre enn forventet, så send ACK på nytt
        elif header_list[0] < packet_num:
            server_socket.sendto(create_packet(header_list[0], ack, 0, 0, "".encode('utf-8')), address)

        # Hvis det mottatte ACK-Nr er lik Basis-NR, send alle pakker opp til neste forventede pakke
        if header_list[1] == base:
            while f'packet{base}' in packets:
                server_socket.sendto(packets[f'packet{base}'], address)
                base += 1

        # Hvis den mottatte pakke størrelsen er mindre enn forventet pakkestørrelse, avslutter vi løkken
        if packet_size != len(packet) - 12:
            kjor = False

        if header_list[2] ==1:
            print("[SERVER] Finished")
            print("[SERVER] closing...")
            time.sleep(1)
            print("[SERVER] closed")
            break





def selective_repeat_server(server_socket, test_case):
    # Oppretter variabler for videre bruk
    buffer = {}
    buffer_size = 10
    buffer_start = 1
    buffer_end = buffer_start + buffer_size - 1
    kjor = 1

    while kjor == 1:

        # For et mer visuelt tiltalende utseende på serveren
        # Motta pakke og parse header
        packet, address = server_socket.recvfrom(2000)
        header = packet[:12]
        header = parse_header(header)

        # Sjekk om pakken er i buffer vinduet
        if header[0] >= buffer_start and header[0] <= buffer_end:
            # Legger til pakken til buffer hvis den ikke allerede er i buffer
            if header[0] not in buffer:
                buffer[header[0]] = packet
                # Hvis pakken er den neste i rekkefølgen, send alle sammenhengende pakker
                if header[0] == buffer_start:
                    while buffer_start in buffer:
                        server_socket.sendto(buffer[buffer_start], address)
                        del buffer[buffer_start]
                        buffer_start += 1
                        buffer_end += 1

        # Send ACK-pakke med mindre testcasene hopper over ACK
        if test_case != "skip_ack":
            ack_packet = create_packet(0, header[0], 0, 0, "".encode('utf-8'))
            server_socket.sendto(ack_packet, address)

        if header[2] ==1:
            print("[SERVER] Finished")
            print("[SERVER] closing...")
            time.sleep(1)
            print("[SERVER] closed")
            break



def selective_repeat_client(client_socket, address, filename, test_case):
    # Setter pakke sin str lik 1460
    packet_size = 1460

    # Oppretter variabler for videre bruk
    packets = {}
    packet_num = 1
    base = 1
    window_size = 5
    packets_sent = False

    # Åpner filen for å lese data
    with open(filename, 'rb') as file:
        # Kjører en loop så til alle pakkene er sendt
        while not packets_sent:
            # Sender pakker med samme window_size
            while packet_num < base + window_size and not packets_sent:
                data = file.read(packet_size)
                if data:

                    if test_case =="loss" and packet_num ==1:
                        packet_num +=1

                    # Oppretter åakker med pakkenr og data, og legger til packet variablen
                    packet = create_packet(packet_num, 0, 0, 0, data)
                    packets[f'packet{packet_num}'] = packet
                    # send packet to receiver
                    client_socket.sendto(packet, address)
                    packet_num += 1
                else:
                    # Alle pakker har blitt sendt
                    packets_sent = True

            # Venter for bekreftelses-pakke fra mottakeren
            try:
                client_socket.settimeout(0.5)
                while True:
                    response, _ = client_socket.recvfrom(2000)
                    header = response[:12]
                    header_list = parse_header(header)
                    # Sjekker om mottat pakken er innenfor window_size
                    if header_list[1] >= base and header_list[1] <= base + window_size - 1:
                        # Sletter bekreftet pakke fra variablen og uppdaterer basen
                        if header_list[1] in packets:
                            del packets[f'packet{header_list[1]}']
                        base = header_list[1] + 1
                    # Sjekker om alle pakker har blitt bekreftet
                    if base > packet_num - 1:
                        packets_sent = True
                        break
            except timeout:
                # Okke noe bekreftelese motatt innenfor gitt tidsramme, forsetter å sende pakker
                pass

        finished_packet = create_packet(0, 0, 1, 0, "".encode("utf-8"))
        client_socket.sendto(finished_packet, address)


def DRTP_server (socket, metode, test_case):

    # Hvis metoden er lik stopWait så kjører vi den
    if metode == 'stopWait':
        stop_and_wait_server(socket, test_case)

    # Hvis metoden er lik GBN så kjører vi den
    elif metode == "GBN":
        gbn_server(socket, test_case)
    # Hvis metoden er lik SR så kjører vi den
    elif metode == "SR":
        selective_repeat_server(socket, test_case)

    # Hvis ingen av tilfelle så skriver vi ut en feilmelding
    else:
        print("Gi en gyldig metode")



def DRTP_client (socket, addresse, metode, fil, test_case):

    # Hvis metoden er lik stopWait så kjører vi den
    if metode == "stopWait":
            stop_and_wait_client(socket, addresse ,fil, test_case)

    # Hvis metoden er lik GBN så kjører vi den
    elif metode == "GBN":
            gbn_client(socket, addresse, fil, test_case)

    # Hvis metoden er lik sr så kjører vi den
    elif metode == "SR":
            selective_repeat_client(socket, addresse, fil, test_case)

    # Hvis ingen av tilfelle så skriver vi ut en feilmelding
    else:
        print("Gi en gyldig metode")






def server(ip, port, reliable, test_case):

    #Oppretter Server
    sock = socket(AF_INET, SOCK_DGRAM)
    sock.bind((ip, port))


    reliable_sjekk, addresse = sock.recvfrom(2000)


    # Printer ut melding om at server er online
    print("[Server] server online")



    #msg = reliable_sjekk.decode('utf-8')
    msg = reliable_sjekk[12:]
    msg = msg.decode('utf-8')




    if msg == reliable:
        reliable_respons = create_packet(0,1,0,0, reliable.encode('utf-8'))
        sock.sendto(reliable_respons,addresse)

    else:
        print("DRTP metodene stemmer ikke overens")

        reliable_respons = create_packet(0,0,0,0,reliable.encode('utf-8'))

        sock.sendto(reliable_respons,addresse)
        sys.exit()


    threeWayHandshakeServer(sock)



    DRTP_server(sock, reliable, test_case)







def client(ip, port, fil, reliable, test_case):

    # Åpne en UDP-socket på klienten
    client_socket = socket(AF_INET, SOCK_DGRAM)
    address = (ip,port)

    reliable_send = create_packet(0,0,0,0, reliable.encode('utf-8'))
    client_socket.sendto(reliable_send, address)

    reliable_godkjenning, address = client_socket.recvfrom(2000)

    header = reliable_godkjenning[:12]

    header_sjekk = parse_header(header)


    if header_sjekk[1] == 1:
        print("DRTP kodene er like")
    else:
        print("DRTP metodene stemmer ikke overens")

        sys.exit()


    threeWayHandshakeClient(client_socket, address)


    DRTP_client(client_socket, address, reliable, fil, test_case )







if __name__ == '__main__':



    # Sjekker argumentet som er gitt når programmet kjører
    # ved å bruke argument parsing for å ta argumentene og sjekke om de er korrekte.

    parser = argparse.ArgumentParser()

    parser.add_argument('--server', '-s', action='store_true', help='server mode')

    parser.add_argument('--client', '-c', action='store_true', help='client mode')

    parser.add_argument('--IP', '-i', type=str, default='127.0.0.1')

    parser.add_argument('--port', '-p', type=int, default=8088)

    parser.add_argument('--reliable', '-r', type=str, required=True)

    parser.add_argument('--test_case', '-t', type=str)

    parser.add_argument('--file', '-f', type=str)



    args = parser.parse_args()


    #Sjekker om test_case inputen ble brukt
    if args.test_case:

        #sjekker hva inputen er og avslutter programmet hvis feil test_case ble gitt
        if args.test_case != "loss" and args.test_case != "skip_ack":
            print("Gi en riktig test case")
            sys.exit()




    # Dette vil gi en feilmelding når klient og server spør samtidig om å være aktiv i et vindu
    if(args.server == True and args.client == True):
        print('Can´t have both server and client command')
        sys.exit()


    #server kode
    elif (args.server == True ):

        # Sjekker noen argumenter, får å se at de er korrekt

        ip_check(args.IP)
        check_port(args.port)

        #starter server
        server(args.IP, args.port, args.reliable, args.test_case)




    #Client kode
    elif (args.client == True):

        # Sjekker noen argumenter, får å se at de er på riktig format
        ip_check(args.IP)
        check_port(args.port)

        #Starter klient
        client(args.IP, args.port, args.file, args.reliable, args.test_case)
