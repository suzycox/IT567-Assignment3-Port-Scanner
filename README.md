# IT567-Assignment3-Port-Scanner

The contained files were written for Python3 and to be run on a Windows machine.

1. The Assignment3_Port_Scanner_Flags.py file is a port scanner capable of using TCP, UDP, ICMP, and traceroute protocols.  It is able to accpet single,ranged, or subnetted hosts, as well as, multiple ports.  After a command is executed, a short response will be returned to the terminal.

        The program accepts the following arguments:
          -h,   --help         prints help information
          -s,   --host         enter single, range (i.e., 192.168.207.41-192.168.207.42), or subnet of hosts to scan
          -p,   --port         enter single or multiple ports (comma separated, no spaces)
          -t,   --TCP          scan using TCP
          -u,   --UDP          scan using UDP
          -i,   --ICMP         scan using ICMP (ping) - no ports requried
          -r,   --traceroute   Run traceroute - no ports required



2. The Assignment3_Port_Scanner_Flags.py file is a GUI capable of sending ICMP requests to a range of hosts.  

        To send a ICMP request, enter the range of hosts in the top box (i.e., 192.168.207.41-192.168.207.42), leave the second box blank, and click the "ICMP" radio button to receive a popup box containing the ping request results (informs the user that the host is either open/closed).
