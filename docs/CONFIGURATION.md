# Configurazione

`/etc/printproxy/printproxy.conf` usa una sintassi rigorosa `CHIAVE=VALORE`.
Non è uno script shell: non sono ammessi `source`, espansioni, sostituzioni di
comando o chiavi sconosciute. Validare sempre prima del riavvio:

```bash
sudo /usr/bin/python3 -I /opt/printproxy/printproxy.py \
  --config /etc/printproxy/printproxy.conf --check-config
```

## Mapping proxy

Le quattro chiavi di rete accettano un valore singolo oppure liste CSV. Le liste
sono correlate esclusivamente per posizione e devono avere la stessa lunghezza:

```ini
LISTEN_IP=10.1.2.220,10.1.2.221,10.1.2.222
LISTEN_PORT=9100,9100,9100
PRINTER_IP=10.1.2.200,10.1.2.201,10.1.2.202
PRINTER_PORT=9100,9100,9100
```

Il risultato è:

```text
proxy-001  10.1.2.220:9100 -> 10.1.2.200:9100
proxy-002  10.1.2.221:9100 -> 10.1.2.201:9100
proxy-003  10.1.2.222:9100 -> 10.1.2.202:9100
```

`proxy-NNN` è un identificatore operativo posizionale. L’identità persistente
di una route installata è invece la tupla completa
`LISTEN_IP:LISTEN_PORT -> PRINTER_IP:PRINTER_PORT`, salvata nello state root-only
dell’installer. Riordinare tuple complete è ammesso; rimuovere o cambiare un
solo endpoint richiede una migrazione esplicita e non viene interpretato come
un normale aggiornamento di configurazione.

Gli spazi intorno agli elementi vengono rimossi. Sono rifiutati: elementi vuoti,
IPv6, indirizzi IPv4 non validi, porte fuori `1..65535`, listener duplicati,
IP stampante duplicati e qualsiasi sovrapposizione fra l'insieme dei
`LISTEN_IP` e quello dei `PRINTER_IP`, anche quando le porte differiscono. Questo
impedisce che una route punti a un altro listener locale formando un ciclo o un
cross-routing. L'unicità dell'IP fisico è inoltre necessaria perché quell'IP è la
chiave sicura della directory archivio.

La configurazione storica a un solo elemento resta valida e conserva il layout
flat esistente:

```ini
LISTEN_IP=10.1.2.220
LISTEN_PORT=9100
PRINTER_IP=10.1.2.200
PRINTER_PORT=9100
```

## Consegna TCP

```ini
PROXY_PROTOCOL=raw
DELIVERY_MODE=transparent_duplex
```

`transparent_duplex` apre una sessione live esclusiva verso la stampante e
inoltra byte opachi in entrambe le direzioni. È la modalità necessaria quando il
gestionale usa DLE EOT, ASB o altre risposte. Non offre replay offline: dopo il
primo invio qualunque esito ambiguo resta `UNKNOWN_PRINT_STATE` e
`retry_allowed=false`.

`store_forward` mantiene il modello storico durevole prima dell'invio, ma è
unidirezionale. Usarlo solo se il pilot ha dimostrato che il gestionale non
attende risposte dalla stampante.

I timeout più importanti sono:

- `INITIAL_DATA_TIMEOUT`: attesa del primo byte;
- `SESSION_IDLE_TIMEOUT`: inattività fra segmenti di una connessione persistente;
- `MAX_SESSION_DURATION`: limite assoluto di una sessione duplex;
- `PRINTER_RESPONSE_TIMEOUT`: coda di risposta dopo il FIN del client;
- `FORWARD_TIMEOUT`: limite totale della fase di inoltro/risposta;
- `MAX_JOB_BYTES` e `MAX_JOB_DURATION`: limiti di un segmento archiviato.

`SPLIT_ON_ESCPOS_CUT=yes` è rifiutato: il byte pattern può comparire in raster e
barcode e non costituisce un framing TCP affidabile.

## Archivi e spool

```ini
DATA_DIR=/var/lib/printproxy/jobs
SPOOL_DIR=/var/lib/printproxy/spool
LOG_DIR=/var/log/printproxy
```

Con un mapping singolo questi percorsi restano invariati per verificare senza
migrazione i ledger esistenti. Con più mapping vengono derivati:

```text
/var/lib/printproxy/jobs/<PRINTER_IP>/
/var/lib/printproxy/spool/<PRINTER_IP>/
```

Ogni stampante ha quindi RAW, sidecar, metadata, manifest e HMAC chain separati.
In una directory per stampante ogni record del ledger è autenticato anche con
`destination=<PRINTER_IP>:<PRINTER_PORT>` e la verifica rifiuta catene copiate o
miste fra route. Il ledger flat storico resta esplicitamente non vincolato per
conservare la compatibilità byte-per-byte dei record già firmati.
La radice flat preesistente non viene spostata né riscritta quando si passa da
uno a più mapping; `printproxyctl verify` la segnala come archivio storico.

## Rendering e OCR

```ini
ENABLE_READABLE_DUMP=yes
SAVE_CLEAN_TXT=yes
SAVE_PDF=yes
PDF_WIDTH_MM=80
```

Il PDF usa sempre i pixel ESC/POS ricostruiti. Il testo raster nel
`.PULITO.txt` viene tentato solo dopo la ricostruzione del canvas, con Tesseract
limitato alle bitmap candidate e soglia di confidenza. Il default è `ita+eng`;
un override amministrativo può essere impostato con
`PRINTPROXY_OCR_LANG`. Mancanza, timeout o bassa confidenza OCR non bloccano il
RAW/PDF: resta un placeholder esplicito.

`PRINTPROXY_OCR_LANG` è una variabile d'ambiente del processo, non una chiave di
`printproxy.conf`. Per renderla persistente creare un drop-in systemd:

```bash
sudo systemctl edit printproxy.service
```

```ini
[Service]
Environment="PRINTPROXY_OCR_LANG=ita+eng"
```

Salvare, quindi eseguire `sudo systemctl daemon-reload` e riavviare il servizio
in una finestra senza sessioni attive. Il valore deve contenere soltanto codici
lingua Tesseract installati, separati da `+`.

## ACL e firewall

Almeno una fra `ALLOWED_NETWORKS` e `ALLOWED_CLIENTS` deve essere valorizzata.
L'ACL applicativa viene verificata da ogni listener prima di leggere il job.
`ENABLE_FIREWALL=yes` aggiunge una tabella nftables dedicata e regole distinte
per ogni coppia listener IP/porta; non cambia policy globali né SSH.

## IP virtuali

`NETWORK_INTERFACE=auto` richiede che tutte le stampanti siano raggiunte dalla
stessa interfaccia della LAN di stampa. Il daemon non crea indirizzi. Il comando
di installazione, solo con l'autorizzazione esplicita `--manage-vips`, può
eseguire DAD e gestire additivamente gli IP mancanti. Senza quel flag gli IP
devono già esistere e l'installer si arresta con diagnostica, senza modificare la
rete.

`VIRTUAL_PREFIX` deve essere uguale al prefisso connesso realmente configurato
sull’interfaccia selezionata; non è sufficiente che VIP e stampante ricadano in
una rete teoricamente più larga.

Vedere [MULTI_PRINTER.md](MULTI_PRINTER.md) per persistenza Debian e collaudo.
