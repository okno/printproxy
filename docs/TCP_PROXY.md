# Proxy TCP full-duplex

## Root cause del blocco applicativo

La precedente architettura `store_forward` leggeva e archiviava il flusso del
gestionale, quindi apriva in un secondo momento una connessione alla stampante e
scriveva il RAW. Non esisteva un reader stampante collegato al writer client.
La carta poteva quindi uscire mentre un eventuale status binario restava sulla
connessione upstream e il gestionale continuava ad attendere.

La correzione non consiste nell'inviare `OK`: consiste nel mantenere entrambe le
direzioni attive durante la stessa sessione TCP.

```text
CLIENT RX  ------------------------------>  PRINTER TX
CLIENT TX  <------------------------------  PRINTER RX
```

## Configurazione richiesta

```ini
PROXY_PROTOCOL=raw
DELIVERY_MODE=transparent_duplex
LISTEN_IP=10.1.2.220
LISTEN_PORT=9100
PRINTER_IP=10.1.2.200
PRINTER_PORT=9100
```

Con liste CSV, ogni indice crea una sessione e un lock indipendenti; una route
non consulta mai la destinazione di un'altra:

```text
10.1.2.220:9100 <-> 10.1.2.200:9100
10.1.2.221:9100 <-> 10.1.2.201:9100
10.1.2.222:9100 <-> 10.1.2.202:9100
```

Un errore di connessione a una stampante chiude soltanto quella sessione. Gli
errori di bind durante lo startup sono invece transazionali: nessun listener
inizia ad accettare finché tutti i bind non sono riusciti.

`DELIVERY_MODE` deve comparire nel file. Durante un upgrade, l'installer rifiuta
un file storico privo della chiave per evitare un passaggio implicito da
store-and-forward a streaming live.

## State machine della connessione

```text
ACCEPT CLIENT
    |
    +-- ACL/concurrency fallita --------------------------> RST CLIENT
    |
    +-- lock stampante occupato --------------------------> RST CLIENT
    |
    v
OPEN PRINTER (prima di leggere payload client)
    |
    +-- connect timeout/refused --------------------------> RST CLIENT
    |
    v
LIVE
    |\
    | +-- task P2C: read printer -> write/drain client
    |
    +---- task C2P: read client -> durable RAW -> write/drain printer
    |
    +-- idle boundary --> sigilla segmento, resta LIVE
    |
    +-- client FIN ----> half-close printer TX, resta in P2C_TAIL
    |
    +-- printer FIN ---> half-close client RX
    |
    +-- RST/error -----> reset peer, esito conservativo UNKNOWN se write possibile
    v
CLOSE + FINALIZE ARCHIVE
```

L'apertura upstream anticipata supporta anche byte server-first. Il relay inverso
è attivo prima del primo payload client.

## Trasparenza byte-opaca

Il proxy non interpreta il reverse stream per decidere cosa inoltrare. Per ogni
chunk ricevuto dalla stampante:

1. aggiorna contatori e SHA-256;
2. salva al massimo `MAX_PRINTER_RESPONSE_CAPTURE_BYTES` nel campo esadecimale
   del JSON;
3. invia l'intero chunk al client;
4. aggiorna il digest dei byte consegnati.

La capture può essere troncata, il relay no. I digest di ricevuto e consegnato
consentono di individuare una chiusura client durante la risposta.

Il rilevamento di `10 04 n` serve solo a incrementare
`realtime_status_queries`; mantiene due byte di tail per riconoscere una sequenza
divisa tra pacchetti TCP. Non rimuove né riscrive quei byte.

## DLE EOT e status

Sequenza prevista:

```text
Gestionale -- 10 04 01 --> Printproxy -- 10 04 01 --> Stampante
Gestionale <--    12    -- Printproxy <--    12    -- Stampante
```

`12` è un esempio binario, non un valore imposto. Printproxy inoltra esattamente
la risposta osservata, che può essere un solo byte, più byte, ASB, dati
proprietari o nessun dato.

Il riferimento Epson [DLE EOT](https://download4.epson.biz/sec_pubs/pos/reference_en/escpos/dle_eot.html)
descrive una risposta status di un byte e raccomanda di non inviare dati
successivi prima di aver ricevuto lo status corrispondente. Il proxy non impone
questa disciplina al gestionale e non emula la stampante: conserva l'ordine TCP.

Il riferimento Epson [GS a](https://download4.epson.biz/sec_pubs/pos/reference_en/escpos/gs_la.html)
descrive Automatic Status Back (ASB), che può inviare più byte iniziali e nuovi
status quando cambiano le condizioni. Per questo il reverse channel non può
essere ridotto a un singolo ACK dopo il job.

POS80BL non è una stampante Epson certificata da questo progetto: formato e bit
supportati devono essere verificati sul suo firmware.

## Half-close

Un client che ha finito di trasmettere può chiamare `shutdown(SHUT_WR)` ma
continuare a leggere. Printproxy:

- registra FIN client;
- invia EOF solo sul lato TX verso la stampante;
- non cancella il task stampante → client;
- attende FIN stampante oppure attività/timeout;
- chiude localmente l'upstream solo alla fine del tail.

Timeout coinvolti:

| Parametro | Scopo |
|---|---|
| `PRINTER_RESPONSE_TIMEOUT` | massimo silenzio ammesso nel tail dopo il half-close |
| `FORWARD_TIMEOUT` | deadline totale del tail e timeout dei drain |
| `MAX_SESSION_DURATION` | limite assoluto della sessione |

Se una risposta legittima arriva dopo `PRINTER_RESPONSE_TIMEOUT`, verrà persa.
Il valore va quindi misurato, non minimizzato arbitrariamente.

## Secondo client: fail-fast

La stampante fisica non può mescolare due sessioni. Quando il lock è occupato,
il secondo client riceve un RST immediato. Non esiste attesa differita e non
esiste replay del suo payload. Questo evita che uno scontrino venga stampato
dopo che il gestionale ha già dichiarato timeout.

La diagnostica attesa è:

```text
DUPLEX_REJECTED_BUSY ...
```

Se il gestionale apre normalmente più connessioni parallele, occorre risolvere a
monte la serializzazione o usare più stampanti/destinazioni; aumentare
`MAX_CONCURRENT_CLIENTS` non rimuove il lock fisico.

## FIN, RST e stato del job

- FIN client pulito può delimitare un job, ma non conferma la stampa.
- FIN stampante conclude il reverse stream; non equivale a carta prodotta.
- RST stampante dopo una write possibile rende il job
  `UNKNOWN_PRINT_STATE`.
- `write()+drain()` conferma soltanto l'accettazione nello stack locale.
- Un byte DLE EOT descrive lo stato richiesto in quell'istante; non è una
  ricevuta universale di completamento del job.

Nessun job duplex è ritentato dal proxy. Una nuova sessione può essere iniziata
solo dal gestionale/operatore sulla base dell'esito applicativo e del controllo
fisico.

## Logging diagnostico

Gli eventi includono timestamp UTC a microsecondi nel campo `timestamp`, session
ID, endpoint, direzione, byte, FIN/RST, timeout e durata. Il formato base del
journal ha precisione al secondo, ma il timestamp evento contiene la precisione
aggiuntiva.

```ini
DEBUG_HEXDUMP=no
DEBUG_HEXDUMP_MAX_BYTES=256
MAX_PRINTER_RESPONSE_CAPTURE_BYTES=65536
```

Con `DEBUG_HEXDUMP=yes`, ogni evento payload può includere solo il prefisso
limitato. L'opzione è disabilitata perché contenuto e status possono essere dati
personali o commercialmente sensibili.

## Confronto direct-vs-proxy con tcpdump

Eseguire la cattura solo in una finestra autorizzata e con un job di test noto.
Sostituire `CLIENT_IP` e `IFACE` con valori reali.

### Scenario A: gestionale → stampante diretta

Il server Printproxy non è nel percorso e normalmente non può vedere questo
traffico. Catturare sul gestionale, sulla stampante o su una porta SPAN/mirror
autorizzata:

```bash
sudo tcpdump -i IFACE -s 0 -nn -U \
  -w /root/printproxy-direct.pcap \
  'tcp port 9100 and host CLIENT_IP and host 10.1.2.200'
```

### Scenario B: gestionale → Printproxy → stampante

Sul server Debian:

```bash
sudo tcpdump -i IFACE -s 0 -nn -U \
  -w /root/printproxy-proxy.pcap \
  'tcp port 9100 and (host CLIENT_IP or host 10.1.2.200)'
```

Fermare con `Ctrl-C` subito dopo un singolo job. Per una vista testuale:

```bash
tshark -r /root/printproxy-direct.pcap \
  -Y 'tcp.len > 0 or tcp.flags.fin == 1 or tcp.flags.reset == 1' \
  -T fields -e frame.time_epoch -e ip.src -e tcp.srcport \
  -e ip.dst -e tcp.dstport -e tcp.flags -e tcp.payload

tshark -r /root/printproxy-proxy.pcap \
  -Y 'tcp.len > 0 or tcp.flags.fin == 1 or tcp.flags.reset == 1' \
  -T fields -e frame.time_epoch -e ip.src -e tcp.srcport \
  -e ip.dst -e tcp.dstport -e tcp.flags -e tcp.payload
```

Confrontare per direzione applicativa, non i sequence number TCP:

- concatenazione payload gestionale → stampante;
- concatenazione payload stampante → gestionale;
- presenza e ordine di `10:04:n` e relativo status;
- tempo tra ultimo byte client, risposta, FIN e RST;
- chiusura/half-close;
- eventuali dati ASB server-first.

Nello scenario proxy esistono due 4-tuple TCP diverse; timing, MSS, segmentazione
e sequence number non devono coincidere con la connessione diretta. Devono
coincidere i byte applicativi concatenati e la semantica di chiusura osservata
dal gestionale.

## Privacy delle catture

Un PCAP può contenere nomi, tavoli, consumazioni, importi, orari, indirizzi e
segreti applicativi. Trattarlo come un archivio di ricevute:

- catturare il minimo indispensabile, senza `-i any` se l'interfaccia è nota;
- usare una directory root-only e verificare permessi `0600`;
- non allegare PCAP o hexdump a ticket pubblici;
- cifrare il trasferimento verso un analista autorizzato;
- definire retention e cancellazione approvate;
- preferire un job sintetico senza dati reali;
- non abilitare contemporaneamente hexdump persistenti se non necessari.

## Limite di validazione

I test automatici usano una stampante TCP simulata e verificano byte, ritardi,
frammentazione, half-close, server-first e secondo client. Non sostituiscono la
cattura direct-vs-proxy e non certificano il firmware POS80BL reale.
