# Guida al Vulnerability Assessment 

## Come viene svolto 

Una volta ricevuta la lista di Indirizzi ip di cui fare il VA si procede con nmap. Il comando usato e il seguente

`read HOST IP && time nmap -T4 -A -Pn $IP -oN $HOST.txt && cat $HOST.txt|grep -oP '\d+/\w+\s' |aw`

il comando ritorna un sommario dei servizi aperti sulla porta, l'hostname e le porte aperte 

A questo punto su Openvas si va a in ordine 

1. Creare Lista di porte ( prese dal comando prima) col nome del hostname
2. Creare il target con l'indirizzo ip , la lista creata sopa e l'opzione consider alive 
3. Creare il task recuperando il target
4. Si manda i ltask 
5. A questo punto si salva i lreport sia in formato pdf che xml
6. Poi usando https://openvas-reporting.sequr.be/en/latest/ si usa col seguente comando `openvasreporting.py -i openvasreport.xml -o {nome file} -f xlsx -l l`

Se fra le porte trovate aperte da nmap ci son oprote con il rpotocollo gttp si procede ad usare Owasp zap
si scrive `http://ip:porta` e si lancia la scansione, anche qui e possibile salvare i lreport in formato xml e pdf 


