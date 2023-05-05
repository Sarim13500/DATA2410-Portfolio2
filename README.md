# DATA2410-Portfolio2
Her er den andre portoføljen/eksamen i faget DATA2410 - Datanettverk og Skytjenester



For å starte applikasjonen må du åpne en terminal.

For å kjøre programmet skriv: 
Python3 application.py

Start serveren med:
Python3 application.py -s

Start klienten med:
Python3 application.py -c

Resten av flagene kan bli aktivert slik:
python3 application.py -s -i <ip_address> -p <port_number> -r <reliable method> -t <test_case> - f <file to transfer>

De pålitelige metodene å velge mellom er:
stopWait, GBN and SR


De test cases som er tilgjenglig:
"skip_ack" også "loss" for pakke tap

