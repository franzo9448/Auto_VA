# Guide to Automated Vulnerability Assessment

Salve, il seguente codice è stato creato per aiutare nella automazione del provcesso di VA.

## Workflow 

Il workflow che il progetto segue è il seguente : 

1. Viene Aperto il file che contiene 
	`HOSTNAME  IP`
2. Per ogni Hostname se viene scelta la funzione Scanner

	Viene fatto un `nmap -T4 -A -Pn`
	Nmap salva il report in formato html nella directory report_nmap
	Nmap salve tutte le porte aperte nella lista open_ports
	Nmap salve tutte le porte aperte con il protocollo http nella lista open_http_ports
	
	Per ogni indirizzo IP viene poi creato il task su openvas con i seguenti passaggi
	Data la lista di open ports viene creata una lista di porte su openvas col HOSTNAME
	Viene creato un target con il nome HOSTNAME , l'indirizzo IP e la lista sopra creata. ATTENZIONE ATTUALMENTE USA IS ALIVE COME METODO DI SCANSIONE
	Viene creato il task col nome HOSTNAME
	
	Poi se la lista http open ports non è vuota viene gestito zap
	Per ogni porta aperta viene lanciato zap e viene salvato un report in report_zap
	

3. Per ogni Hostname se viene scelta la funzione Report,

	ATTENZIONE NON LANCIARLA PRIMA DI AVER FINITO TUTTI I TASK.
	Itera all'interno del documento, per ogni hostname scarica il report in formato pdf e xml nella cartella report_openvas
	Inoltre genera un excell a partire dai report di Zap
	

## Utilizzo

Prima di passare al comando python , ci sono due cose da fare 

1. Modificare la connessione di Openvas in base a dove si trova il gvdm.sock 
2. Modificarel'apikey di owasp zap

Per fare la scansione completa

`python main.py scanner {list ip.txt} {openvas username} {openvas password}`.

Per fare la reportistica completa

`python main.py repoirt {list ip.txt} {openvas username} {openvas password}`

Per fare solo nmap

`python main.py nmap {list ip.txt} `

Per fare Zap e Nmap

`python main.py zap {list ip.txt} `

Per fare Report Zap 

`python main.py report_zap {list ip.txt} `