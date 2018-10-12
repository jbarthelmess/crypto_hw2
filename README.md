# Cryptography HW2 by Josh Barthelmess

This is a very basic implementation of the Diffie Helman Key distribution 
algorithm and The Needer Schroeder Protocol

To compile and run:

gcc kdc.c -o kdc.exe
gcc hw2.c -o hw2.exe

./kdc.exe <PORT>

./hw2.exe <NAME> <PORT> <KDC_PORT> [<CONNECTOR_NAME>]

The kdc.exe file should be run first and then the client files can be run in any order.
If the file is the initiator, <CONNECTOR_NAME> should be used to indicate who they are
talking to, and port should be the port of the listening client. <KDC_PORT> is the port
on which KDC is listening on. 


