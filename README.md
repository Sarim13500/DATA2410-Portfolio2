# DATA2410-Portfolio2
Here is the second porfolio/exam in the subject DATA2410 - Datanettverk og Skytjenester


To start the application you will need to open a terminal.

To run the program write:
Python3 application.py

Start server with
Python3 application.py -s

Start the client with

Python3 application.py -c

rest of the flags can be activated like this:

python3 application.py -s -i <ip_address> -p <port_number> -r <reliable method> -t <test_case> - f <file to transfer>

The reliable method to choose from are:
stopWait, GBN and SR


The test cases that are availale are:
"skip_ack" as well as "loss" for packet loss

