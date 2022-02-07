# An example script to create a port scanning
import socket # for socket
import sys
import ipaddress

#ADDRESS_OF_DEVICE_TO_SCAN = "192.168.0.235" #write an address here
def validate_ip_address(address):
    try:
        ip = ipaddress.ip_address(address)
        print("IP address {} is valid. The object returned is {}".format(address, ip))
        return ip
    except ValueError:
        print("IP address {} is not valid".format(address))
        return 0


def main(addr):
    if not validate_ip_address(addr):
        return 0
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
        for port in range(1,25):
            a=s.connect_ex((host_ip, port))
            socket.setdefaulttimeout(1)
            if not a:
                print("Port {} is open".format(port))
    except socket.error:
        print("Socket error")
    print("Script finished")
    
if __name__ == "__main__":
    main(sys.argv[1])