#Compatable with Python 3
#python "C:\Users\Suzy\Documents\Suzy BYU~MISM2\4. IT567 - Cybersecurity and Pen Testing\Assignments\Assignment3 - Port Scanner\Assignment3_port_Scanner_Flags.py"
import socket

import struct

import subprocess
import sys

import ipaddress
import getopt

from datetime import datetime

from tkinter import *
import tkinter.messagebox


def TCPscan():
    radioValue = relProtocol.get()
    tkinter.messagebox.showinfo("TCP Scan:", radioValue)

def ICMPscan():
    host = hostEntry.get()
    ports = portEntry.get()
    protocol = relProtocol.get()

    tkinterMessage = ""

    if "-" in host:
        host = host.split("-")
        start = int((host[0].split(".",3))[3])
        end = int((host[1].split(".",3))[3])
        subnet = (host[0].split(".",3))[0] + "." + (host[0].split(".",3))[1] + "." + (host[0].split(".",3))[2] + "."
        print (subnet)
        print (host)
        print(start, end)
        hostIP = []
        for i in range(start,end+1):
            currentHost = subnet + str(i)
            hostIP.append([int(ipaddress.ip_address(currentHost))])
        print (*hostIP, sep=", ")
        hostType = "subnet"


    elif "/" not in host:
        try:
            hostIP = socket.gethostbyname(host)
            hostType = "singleHost"
        except socket.gaierror:
            print ("Unable to connect to host: Invalid host")
            sys.exit()

    else:
        hostIP = []
        for h in ipaddress.IPv4Network(host):
            hostIP.append([int(h)])
            hostType = "subnet"
        print(*hostIP, sep = ", ")


    startTime = datetime.now()

## ICMP SCAN ##
    tkinterMessage = tkinterMessage + "ICMP Scan:" + hostEntry.get() + '\n' + '\n'



    if (hostType == "singleHost"):
        try:
            response = subprocess.check_output(
                ['ping', '-n', '1', hostIP],
                stderr=subprocess.STDOUT,  # get all output
                universal_newlines=True  # return string not bytes
            )
            print(response)
            if "Lost = 0" in response:
                tkinterMesasge = tkinterMessage + hostIP + "is up!" + '\n'

            else:
                tkinterMessage = tkinterMessage + hostIP + "is down!" + '\n'

        except subprocess.CalledProcessError:
            response = None
            tkinterMessage = tkinterMessage + hostIP + "is down" + '\n'



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
                    tkinterMessage = tkinterMessage + currentHost + "is up!" + '\n'

                else:
                    tkinterMessage = tkinterMessage + currentHost + "is down!" + '\n'


            except subprocess.CalledProcessError:
                response = None
                tkinterMessage = tkinterMessage + currentHost + "is down" + '\n'





    tkinter.messagebox.showinfo("IMCP Scan:", tkinterMessage)


app = Tk()
app.title("Port Scanner GUI")

#Hosts
labelText = StringVar()
labelText.set("Please Enter Host(s)")
label1 = Label(app, textvariable=labelText, height=4)
label1.pack()

hostEntry = StringVar(None)
host = Entry(app, textvariable=hostEntry)
host.pack()

#Ports
labelText2 = StringVar()
labelText2.set("Please Enter Port(s)")
label2 = Label(app, textvariable=labelText2, height=4)
label2.pack()

portEntry = StringVar(None)
ports = Entry(app, textvariable=portEntry)
ports.pack()

#Protocol
labelText3 = StringVar()
labelText3.set("Please Select Desired Protocol")
label3 = Label(app, textvariable=labelText3, height=4)
label3.pack()

relProtocol = StringVar()
relProtocol.set(None)
radio1 = Radiobutton(app, text="TCP", value="TCP", variable=relProtocol, command=TCPscan).pack()
radio1 = Radiobutton(app, text="ICMP", value="ICMP", variable=relProtocol, command=ICMPscan).pack()

button1 = Button(app, text="Scan", width=20)

app.mainloop()
