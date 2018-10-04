#Compatable with Python 3
#python "C:\Users\Suzy\Documents\Suzy BYU~MISM2\4. IT567 - Cybersecurity and Pen Testing\Assignments\Assignment3 - Port Scanner\Assignment3_port_Scanner_Flags.py"
import socket
import struct
import subprocess
import sys
import ipaddress
import getopt
import scapy
from scapy.layers.inet import IP, ICMP, UDP
from scapy.sendrecv import sr
from datetime import datetime
import re

########################################
##### SET UP COMMAND-LINE SWITCHES #####
########################################
fullCmdArguments = sys.argv

argumentList = fullCmdArguments[1:]

unixOptions = "hs:p:tuir"
gnuOptions = ["help", "host=", "port=", "TCP", "UDP", "ICMP", "traceroute"]

try:
    arguments, values = getopt.getopt(argumentList, unixOptions, gnuOptions)
except getopt.error as err:
    # output error, and return with an error code
    print (str(err))
    sys.exit(2)


for currentArgument, currentValue in arguments:

########################################
############# HELP SWITCH ##############
########################################
    if currentArgument in ("-h", "--help"):
        helpText = '\n' + "Arguments:" + '\n'
        helpText = helpText + '\t' + "-h,   --help         prints help information" + '\n'
        helpText = helpText + '\t' + "-s,   --host         enter single, range (i.e., 192.168.207.41-192.168.207.42), or subnet of hosts to scan" + '\n'
        helpText = helpText + '\t' + "-p,   --port         enter single or multiple ports (comma separated, no spaces)" + '\n'
        helpText = helpText + '\t' + "-t,   --TCP          scan using TCP" + '\n'
        helpText = helpText + '\t' + "-u,   --UDP          scan using UDP" + '\n'
        helpText = helpText + '\t' + "-i,   --ICMP         scan using ICMP (ping) - no ports requried" + '\n'
        helpText = helpText + '\t' + "-r,   --traceroute   Run traceroute - no ports required" + '\n'
        print (helpText)

########################################
############# HOST SWITCH ##############
########################################
    elif currentArgument in ("-s", "--host"):
        #print ("In Hosts Flag")

        #If valid hosts swtich, create head of HTML Report that will be added to throughout
        htmlReport = open('ScanningReport.html','w')
        htmlText = "<html><head><style>table {font-family: arial, sans-serif;border-collapse: collapse;width: 100%;}"
        htmlText = htmlText + "td, th {border: 1px solid #dddddd; text-align: left; padding: 8px; } tr:nth-child(even) {background-color: #dddddd;}</style></head><body>"


        host = currentValue
        #save users original host input to use in headers
        hostUserInput = host

        #check to see if the user input host is a range
        if "-" in host:
            host = host.split("-")
            start = int((host[0].split(".",3))[3])
            end = int((host[1].split(".",3))[3])
            subnet = (host[0].split(".",3))[0] + "." + (host[0].split(".",3))[1] + "." + (host[0].split(".",3))[2] + "."
            #print (subnet)
            #print (host)
            #print(start, end)
            hostIP = []
            for i in range(start,end+1):
                currentHost = subnet + str(i)
                hostIP.append([int(ipaddress.ip_address(currentHost))])
            #print (*hostIP, sep=", ")
            hostType = "subnet"

        #check to see if the user input host is an individual host
        elif "/" not in host:
            try:
                hostIP = socket.gethostbyname(host)
                hostType = "singleHost"
                #print ("singleHost:", hostIP)
            except socket.gaierror:
                print ("Unable to connect to host: Invalid host")
                sys.exit()

        #check to see if the user input host is a subnet
        else:
            hostIP = []
            for h in ipaddress.IPv4Network(host):
                hostIP.append([int(h)])
                hostType = "subnet"
            #print(*hostIP, sep = ", ")





########################################
############# PORT SWITCH ##############
########################################
    elif currentArgument in ("-p", "--port"):
        #print ("In Port Flag")


        startTime = datetime.now()
        ports = (currentValue.split(","))
        #print ("Ports Values:", ports)

        #Single Host Scan with Multiple Ports
        if (hostType == "singleHost"):
            print ("-------------------------------------------------")
            print ("Scanning Single Host", hostIP)
            print ("Scan started at", startTime)
            print ("-------------------------------------------------")

        if (hostType == "subnet"):
            print ("-------------------------------------------------")
            print ("Scanning Subnet/Range", hostUserInput)
            print ("Scan started at", startTime)
            print ("-------------------------------------------------")



########################################
############## TCP SWITCH ##############
########################################
    elif currentArgument in ("-t", "--TCP"):
        #print ("In TCP Flag")
        if (hostType == "singleHost"):

            #Add Table Headers to HTML
            htmlText = htmlText + "<h2>TCP Scan: " + str(hostIP) + "<table><tr> <th>Host</th> <th>Port</th> <th>Status</th> </tr>"

            #build and send TCP packets for single host, multiple ports
            try:
                for port in ports:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    print (hostIP)
                    result = sock.connect_ex((hostIP, int(port)))

                    if result == 0:
                        print ("Port " + str(port) + ": Open")
                        #Add host, port, and status to HTML
                        htmlText = htmlText + "<tr> <td>" + hostIP + "</td> <td>" + str(port) +"</td> <td>Open</td> </tr>"

                    else:
                        print ("Port " + str(port) + ": Closed")
                        #Add host, port, and status to HTML
                        htmlText = htmlText + "<tr> <td>" + hostIP + "</td> <td>" + str(port) + "</td> <td>Closed</td> </tr>"

                    sock.close()

            except KeyboardInterrupt:
                print ("Exiting Program")
                sys.exit()

            except socket.gaierror:
                print ("Unable to connect to host")
                sys.exit()

            #Write and save the HTML generated Report
            htmlReport.write(htmlText)
            htmlReport.close()



        elif (hostType == "subnet"):

            #Add Table Headers to HTML
            htmlText = htmlText + "<h2>TCP Scan: " + str(hostUserInput) + "<table><tr> <th>Host</th> <th>Port</th> <th>Status</th> </tr>"

            #build and send TCP packets for host range/subnet, multiple ports
            try:
                #print("SUBNET HOSTS:", hostIP)
                for h in hostIP:
                    currentHost = int(str(h).strip('[]'))
                    print (socket.inet_ntoa(struct.pack('!L', currentHost)))

                    try:
                        for port in ports:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            result = sock.connect_ex((str(currentHost), int(port)))
                            if result == 0:
                                print ("Port " + str(port) + ": Open")
                                #Add host, port, and status to HTML
                                htmlText = htmlText + "<tr> <td>" + socket.inet_ntoa(struct.pack('!L', currentHost)) + "</td> <td>" + str(port) + "</td> <td>Open</td> </tr>"

                            else:
                                print ("Port " + str(port) + ": Closed")
                                #Add host, port, and status to HTML
                                htmlText = htmlText + "<tr> <td>" + socket.inet_ntoa(struct.pack('!L', currentHost)) + "</td> <td>" + str(port) + "</td> <td>Closed</td> </tr>"

                            sock.close()
                    except KeyboardInterrupt:
                        print ("Exiting Program")
                        sys.exit()

                    except socket.gaierror:
                        print ("Unable to connect to host")
                        sys.exit()

            except KeyboardInterrupt:
                print ("Exiting Program")
                sys.exit()

            except socket.gaierror:
                print ("Unable to connect to host")
                sys.exit()

            #Write and save the HTML generated Report
            htmlReport.write(htmlText)
            htmlReport.close()



########################################
############## UDP SWITCH ##############
########################################
    elif currentArgument in ("-u", "--UDP"):
        #print ("In UDP Flag")

        if (hostType == "singleHost"):

            #Add Table Headers to HTML
            htmlText = htmlText + "<h2>UDP Scan: " + str(hostIP) + "<table><tr> <th>Host</th> <th>Port</th> <th>Status</th> </tr>"

            #build and send UDP packets for single host, multiple ports
            try:
                for port in ports:
                    ip = IP(dst=host)
                    udp = UDP(dport=int(port),sport = 123)
                    packet = ip/udp
                    response = sr(packet,verbose=False,timeout = 20)

                    try:
                       check = response[0][ICMP][0][1][ICMP]
                       print("Port {} on {} is closed".format(port,host))
                       #Add host, port, and status to HTML
                       htmlText = htmlText + "<tr> <td>" + hostIP + "</td> <td>" + str(port) + "</td> <td>Closed</td> </tr>"

                    except IndexError:
                       print("Port {} on {} is open|filtered".format(port,host))
                       #Add host, port, and status to HTML
                       htmlText = htmlText + "<tr> <td>" + hostIP + "</td> <td>" + str(port) +"</td> <td>open|filtered</td> </tr>"

            except KeyboardInterrupt:
                print ("Exiting Program")
                sys.exit()

            except socket.gaierror:
                print ("Unable to connect to host")
                sys.exit()

            #Write and save the HTML generated Report
            htmlReport.write(htmlText)
            htmlReport.close()



        elif (hostType == "subnet"):

            #Add Table Headers to HTML
            htmlText = htmlText + "<h2>TCP Scan: " + str(hostUserInput) + "<table><tr> <th>Host</th> <th>Port</th> <th>Status</th> </tr>"

            #build and send UDP packets for host range/subnet, multiple ports
            try:
                #print("SUBNET HOSTS:", hostIP)
                for h in hostIP:
                    currentHost = int(str(h).strip('[]'))
                    print (socket.inet_ntoa(struct.pack('!L', currentHost)))

                    try:
                        for port in ports:
                            ip = IP(dst=host)
                            udp = UDP(dport=int(port),sport = 123)
                            packet = ip/udp
                            response = sr(packet,verbose=False,timeout = 20)
                            #if response, UDP port closed
                            try:
                               check = response[0][ICMP][0][1][ICMP]
                               print("Port {} on {} is closed".format(port, socket.inet_ntoa(struct.pack('!L', currentHost))))
                               #Add host, port, and status to HTML
                               htmlText = htmlText + "<tr> <td>" + socket.inet_ntoa(struct.pack('!L', currentHost)) + "</td> <td>" + str(port) + "</td> <td>Closed</td> </tr>"

                            #if no response, UDP port open|filtered
                            except IndexError:
                               print("Port {} on {} is open|filtered".format(port, socket.inet_ntoa(struct.pack('!L', currentHost))))
                               #Add host, port, and status to HTML
                               htmlText = htmlText + "<tr> <td>" + socket.inet_ntoa(struct.pack('!L', currentHost)) + "</td> <td>" + str(port) + "</td> <td>open|filtered</td> </tr>"


                    except KeyboardInterrupt:
                        print ("Exiting Program")
                        sys.exit()

                    except socket.gaierror:
                        print ("Unable to connect to host")
                        sys.exit()

            except KeyboardInterrupt:
                print ("Exiting Program")
                sys.exit()

            except socket.gaierror:
                print ("Unable to connect to host")
                sys.exit()

            #Write and save the HTML generated Report
            htmlReport.write(htmlText)
            htmlReport.close()




########################################
############# ICMP SWITCH ##############
########################################
    elif currentArgument in ("-i", "--ICMP"):
        #print ("In ICMP Flag")

        startTime = datetime.now()
        print ("-------------------------------------------------")
        print ("ICMP Scan:", hostUserInput)
        print ("Scan started at", startTime)
        print ("-------------------------------------------------")

        #Add Table Headers to HTML
        htmlText = htmlText + "<h2>ICMP Scan: " + hostUserInput + "<table><tr> <th>Port</th> <th>Status</th> </tr>"

        #send ping requests for single host, no ports
        if (hostType == "singleHost"):
            try:
                response = subprocess.check_output(
                    ['ping', '-n', '1', hostIP],
                    stderr=subprocess.STDOUT,  # get all output
                    universal_newlines=True  # return string not bytes
                )
                if "Lost = 0" in response:
                    print (hostIP, "is up!")
                    #Add host, port, and status to HTML
                    htmlText = htmlText + "<tr> <td>" + hostIP + "</td> <td>Open</td> </tr>"

                else:
                    print (hostIP, "is down!")
                    #Add host, port, and status to HTML
                    htmlText = htmlText + "<tr> <td>" + hostIP + "</td> <td>Closed</td> </tr>"

            except subprocess.CalledProcessError:
                response = None
                print (hostIP, "is down")
                #Add host, port, and status to HTML
                htmlText = htmlText + "<tr> <td>" + hostIP + "</td> <td>Closed</td> </tr>"


        #send ping requests for host range/subnet, no ports
        elif (hostType == "subnet"):
            #print("SUBNET HOSTS:", hostIP)
            for h in hostIP:
                currentHost = int(str(h).strip('[]'))
                currentHost = socket.inet_ntoa(struct.pack('!L', currentHost))

                try:
                    response = subprocess.check_output(
                        ['ping', '-n', '1', currentHost],
                        stderr=subprocess.STDOUT,  # get all output
                        universal_newlines=True  # return string not bytes
                    )

                    if "Lost = 0" in response:
                        print (currentHost, "is up!")
                        #Add host, port, and status to HTML
                        htmlText = htmlText + "<tr> <td>" + currentHost + "</td> <td>Open</td> </tr>"

                    else:
                        print (currentHost, "is down")
                        #Add host, port, and status to HTML
                        htmlText = htmlText + "<tr> <td>" + currentHost + "</td> <td>Closed</td> </tr>"

                except subprocess.CalledProcessError:
                    response = None
                    print (currentHost, "is down")
                    #Add host, port, and status to HTML
                    htmlText = htmlText + "<tr> <td>" + currentHost + "</td> <td>Closed</td> </tr>"

        #Write and save the HTML generated Report
        htmlReport.write(htmlText)
        htmlReport.close()









########################################
############# TRACEROUTE ###############
########################################
    elif currentArgument in ("-r", "--traceroute"):
        #print ("In Traceroute Flag")

        startTime = datetime.now()
        print ("-------------------------------------------------")
        print ("Traceroute:", hostUserInput)
        print ("Scan started at", startTime)
        print ("-------------------------------------------------")

        #Add Table Headers to HTML
        htmlText = htmlText + "<h2>Traceroute: " + hostUserInput + "<table><tr> <th>Host</th> <th>Hops</th> </tr>"

        #Build traceroute for single host, no ports
        if (hostType == "singleHost"):
            try:
                p = subprocess.Popen(["tracert", '-d', '-w', '100', host],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

                #group tracert responses into one string result
                result = ""
                while True:
                    line = p.stdout.readline()
                    if not line:
                        break
                    result = result + str(line) + '/n'
                p.wait()

                #pull all IPs from tracert response
                ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', result)
                #delete first ip from list as this is just the description of the Tracert Task
                ip.pop(0)

                #print out all hops from ip list
                count = 0
                for i in ip:
                    count = count + 1
                    print (str(count), "Hop:", i)
                    #Add host, port, and status to HTML
                    htmlText = htmlText + "<tr> <td>" + host + "</td> <td>" + str(count) + '. '  + i + "</td>"

            except subprocess.CalledProcessError:
                response = None
                print (hostIP, "is down")
                #Add host, port, and status to HTML
                htmlText = htmlText + "<tr> <td>" + host + "</td> <td>Unable to Connect</td> </tr>"


        #Build traceroute for host range/subnet, no ports
        elif (hostType == "subnet"):
            #print("SUBNET HOSTS:", hostIP)
            for h in hostIP:
                currentHost = int(str(h).strip('[]'))
                currentHost = socket.inet_ntoa(struct.pack('!L', currentHost))

                try:
                    p = subprocess.Popen(["tracert", '-d', '-w', '100', currentHost],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

                    #group tracert responses into one string result
                    result = ""
                    while True:
                        line = p.stdout.readline()
                        if not line:
                            break
                        result = result + str(line) + '/n'
                    p.wait()

                    #pull all IPs from tracert response
                    ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', result)
                    #delete first ip from list as this is just the description of the Tracert Task
                    ip.pop(0)

                    print (currentHost, "traceroute:")
                    #print out all hops from ip list
                    count = 0
                    for i in ip:
                        count = count + 1
                        print (str(count), "Hop:", i)
                        #Add host, port, and status to HTML
                        htmlText = htmlText + "<tr> <td>" + currentHost + "</td> <td>" + str(count) + '. ' + i + "</td>"

                except subprocess.CalledProcessError:
                    response = None
                    print (currentHost, "is down")
                    #Add host, port, and status to HTML
                    htmlText = htmlText + "<tr> <td>" + currentHost + "</td> <td>Unable to Connect</td> </tr>"

        #Write and save the HTML generated Report
        htmlReport.write(htmlText)
        htmlReport.close()







########################################
############ SCAN DURATION #############
########################################
if currentArgument not in ("-h", "--help"): #do not print for help argument
    print ("-------------------------------------------------")
    print ("Scan Duration:", datetime.now() - startTime)
