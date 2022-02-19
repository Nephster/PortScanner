# An example script to create a port scanning
import socket # for socket
import sys
import ipaddress
import argparse
import re
#ADDRESS_OF_DEVICE_TO_SCAN = "192.168.0.235" #write an address here
def validate_ip_address(address):
    try:
        ip = ipaddress.ip_address(address)
        #print("IP address {} is valid. The object returned is {}".format(address, ip))
        return ip
    except ValueError:
        print("IP address {} is not valid".format(address))
        return 0


def main():
    parser = argparse.ArgumentParser(description="Port scanner",epilog="Usage: PortScanner.py -a 192.168.0.1 -p 1-25")
    parser.add_argument("-a","--address",help="HostName or IP address of SSH Server")
    parser.add_argument("-p", "--port", help="Port range")
    args = parser.parse_args()
    addr = args.address
    port_range = args.port
    #print(port_range)
    m = re.match(r"([0-9]+\-[0-9]+)",port_range)
    if m == None:
        print("Wrong port-range")
        return
    else:
        port_range = m.group().split("-")
    if not validate_ip_address(addr):
        return 0
    #print(port_range) 
    print("Scanning:{}".format(addr))
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print ("Socket successfully created")
    except socket.error as err:
        print ("socket creation failed with error %s" %(err))

    try:
        host_ip = socket.gethostbyname(addr)
    except socket.gaierror:
        print ("there was an error resolving the host")
        sys.exit()

    try:
        for port in range(int(port_range[0]),int(port_range[1]+1)):
            a=s.connect_ex((host_ip, port))
            socket.setdefaulttimeout(1)
            if not a:
                print("Port: {} state: {}".format(port,"open"))
            else:
                print("Port: {} state: {}".format(port,"close"))
    except socket.error:
        print("Socket error")
    print("Script finished")
    
if __name__ == "__main__":
    main()