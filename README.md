# Printproxy RAW/JetDirect full-duplex

Printproxy è un proxy TCP trasparente multi-stampante per stampe di cortesia
RAW/ESC-POS. Il gestionale si collega a uno degli indirizzi virtuali del server
Debian; la `ProxyInstance` associata apre una sessione verso la stampante reale,
inoltra simultaneamente entrambi i flussi senza reinterpretarli e archivia una
copia del flusso client → stampante nella directory di quella stampante.

```text
Gestionale  <==== TCP byte-opaco ====>  Printproxy  <==== TCP byte-opaco ====>  POS80BL
                  10.1.2.220:9100                         10.1.2.200:9100
                         |
                         +--> RAW + TXT tecnico + PULITO.TXT + PDF + JSON
```

La modalità di produzione deve essere dichiarata esplicitamente:

```ini
DELIVERY_MODE=transparent_duplex
```

Non viene mai inventato un `OK`, ACK `0x06` o altro byte. Una richiesta ESC/POS
`DLE EOT n` (`10 04 n`) raggiunge la stampante e la risposta reale torna al
gestionale byte per byte. Anche dati server-first e risposte frammentate sono
inoltrati. Il conteggio diagnostico di `DLE EOT` non modifica il payload.

> Un byte di stato, un `write()+drain()` riuscito o la chiusura TCP non provano
> che carta, stampa e taglio siano stati completati. Per questo lo stato
> terminale resta `SENT_UNCONFIRMED`, mai `PRINTED`.

## Topologia e vincoli

- `10.1.2.220` è la VIP del servizio; `10.1.2.235` può restare l'IP di
  amministrazione del server.
- `10.1.2.200:9100` è la stampante reale RAW/JetDirect.
- Non sono usati ARP spoofing, NAT, IP forwarding o modifica del gateway.
- Il bind su `0.0.0.0` è rifiutato: il listener usa solo la VIP dedicata.
- Un'unica sessione live può possedere la stampante. Un secondo client mentre la
  prima sessione è attiva viene chiuso con RST immediatamente: non viene messo in
  attesa e nessun suo byte raggiunge la stampante.
- Il client può eseguire `shutdown(SHUT_WR)`: Printproxy propaga il half-close
  verso la stampante ma mantiene vivo stampante → client fino a FIN della
  stampante o ai timeout di risposta configurati.
- Un gap di inattività può sigillare un segmento d'archivio senza chiudere la
  sessione TCP persistente né la connessione upstream.

RAW TCP/9100 non offre un job ID universale, una ricevuta applicativa standard o
una garanzia exactly-once. Il progetto protegge l'identità digitale dei byte e
tratta in modo conservativo ogni esito incerto.

## Modalità di consegna

| Valore | Semantica | Risposte stampante |
|---|---|---|
| `transparent_duplex` | inoltro live simultaneo, una sessione esclusiva | inoltrate al client byte per byte |
| `store_forward` | modalità legacy: archivia, poi inoltra con worker separato | non inoltrate al client |

`transparent_duplex` non esegue replay dei job. Dal momento in cui una write
verso la stampante è anche solo possibile, un crash o errore produce
`UNKNOWN_PRINT_STATE`; prima di qualsiasi write produce `DUPLEX_ABORTED`. Entrambi
hanno `retry_allowed=false`. Il gestionale osserva l'errore TCP e decide se
iniziare una nuova sessione.

`store_forward` resta disponibile solo per compatibilità e per smaltire in modo
controllato eventuali job legacy già presenti. Non deve essere usato se il
gestionale attende status o risposte ESC/POS.

## Installazione

Repository pubblico: <https://github.com/okno/printproxy>.

```bash
sudo apt-get update
sudo apt-get install --no-install-recommends -y git ca-certificates
sudo install -d -m 0755 -o "$(id -un)" -g "$(id -gn)" /srv/printproxy-src
git clone https://github.com/okno/printproxy.git /srv/printproxy-src
cd /srv/printproxy-src
git fetch --tags --prune origin
git switch --detach <TAG_RELEASE_VERIFICATO>
getent group printproxy >/dev/null || sudo groupadd --system printproxy
sudo install -d -m 0750 -o root -g printproxy /etc/printproxy
if ! sudo test -e /etc/printproxy/printproxy.conf; then
  sudo install -m 0640 -o root -g printproxy \
    config/printproxy.conf /etc/printproxy/printproxy.conf
fi
sudoedit /etc/printproxy/printproxy.conf
sudo /usr/bin/python3 -I ./printproxy.py \
  --config /etc/printproxy/printproxy.conf --check-config
sudo ./install.sh --manage-vips
```

Non eseguire l'installer prima di aver adattato mapping, ACL e modalità di
consegna. La procedura completa e le varianti con VIP gestite esternamente sono
in [GIT_DEPLOYMENT.md](docs/GIT_DEPLOYMENT.md).

L'installer supporta Debian 12/13, installa solo le dipendenze mancanti
(compresi ReportLab e Tesseract ita+eng), valida configurazione, storage locale,
unit systemd e logrotate. `--manage-vips` è l'autorizzazione esplicita a
eseguire DAD e creare additivamente gli IP virtuali mancanti; senza il flag gli
indirizzi devono già essere configurati. Non vengono riscritti profili
NetworkManager, file `.network`, route, gateway o `/etc/network/interfaces`.

Dettagli completi per clone, tag, upgrade, rollback e rimozione del clone sono in
[GIT_DEPLOYMENT.md](docs/GIT_DEPLOYMENT.md). L'installazione operativa è descritta
anche in [INSTALLATION.md](docs/INSTALLATION.md).

### Upgrade da una versione precedente

L'upgrade non sceglie silenziosamente una nuova semantica. Se
`/etc/printproxy/printproxy.conf` non contiene `DELIVERY_MODE`, `install.sh` si
arresta.

1. Riportare temporaneamente il gestionale alla stampante diretta o aprire una
   finestra senza nuove stampe.
2. Creare backup di configurazione, chiave, `DATA_DIR` e `SPOOL_DIR`.
3. Fermare il servizio e controllare gli stati legacy:

   ```bash
   sudo systemctl stop printproxy
   sudo printproxyctl queue --all --json
   ```

4. Se esistono job legacy ritentabili, riavviare temporaneamente con
   `DELIVERY_MODE=store_forward` e smaltirli secondo la procedura operativa. La
   modalità duplex rifiuta l'avvio in presenza di backlog legacy replayable.
5. Modificare esplicitamente il file con:

   ```ini
   DELIVERY_MODE=transparent_duplex
   ```

6. Validare e reinstallare la release:

   ```bash
   sudo /usr/bin/python3 -I /srv/printproxy-src/printproxy.py \
     --config /etc/printproxy/printproxy.conf --check-config
   cd /srv/printproxy-src
   sudo ./install.sh --manage-vips
   ```

7. Eseguire self-test e test duplex con stampante/emulatore prima di cambiare il
   gestionale verso la VIP.

Non copiare automaticamente la configurazione `.dist` sopra quella attiva: IP,
ACL, percorsi e timeout devono essere riesaminati.

## Configurazione essenziale

File attivo: `/etc/printproxy/printproxy.conf`, sintassi rigorosa `KEY=VALUE`.

```ini
PROXY_PROTOCOL=raw
DELIVERY_MODE=transparent_duplex

LISTEN_IP=10.1.2.220
LISTEN_PORT=9100
PRINTER_IP=10.1.2.200
PRINTER_PORT=9100

JOB_END_MODE=hybrid
IDLE_TIMEOUT=3
INITIAL_DATA_TIMEOUT=15
SESSION_IDLE_TIMEOUT=300
MAX_JOB_DURATION=300
MAX_SESSION_DURATION=900

CONNECT_TIMEOUT=5
FORWARD_TIMEOUT=30
PRINTER_RESPONSE_TIMEOUT=5

MAX_JOB_BYTES=67108864
MAX_PRINTER_RESPONSE_CAPTURE_BYTES=65536
DEBUG_HEXDUMP=no

ENABLE_READABLE_DUMP=yes
SAVE_CLEAN_TXT=yes
SAVE_PDF=yes
PDF_WIDTH_MM=80
DEFAULT_CODEPAGE=cp858
ENABLE_HEX_DUMP=no
```

Le stesse quattro chiavi di rete accettano liste CSV posizionali:

```ini
LISTEN_IP=10.1.2.220,10.1.2.221,10.1.2.222
LISTEN_PORT=9100,9100,9100
PRINTER_IP=10.1.2.200,10.1.2.201,10.1.2.202
PRINTER_PORT=9100,9100,9100
```

Le lunghezze devono coincidere; IP, porte, elementi vuoti e duplicati vengono
validati prima di aprire socket. Vedere [CONFIGURATION.md](docs/CONFIGURATION.md)
e [MULTI_PRINTER.md](docs/MULTI_PRINTER.md).

| Parametro | Effetto |
|---|---|
| `IDLE_TIMEOUT` | delimita un segmento d'archivio, non tronca di per sé il reverse stream |
| `PRINTER_RESPONSE_TIMEOUT` | attesa di inattività del tail stampante dopo il half-close client |
| `CONNECT_TIMEOUT` | limite per aprire la connessione alla stampante |
| `FORWARD_TIMEOUT` | limite dei drain e deadline totale del tail di risposta |
| `MAX_SESSION_DURATION` | limite assoluto della sessione live |
| `MAX_PRINTER_RESPONSE_CAPTURE_BYTES` | limita solo l'anteprima nel JSON; il relay non viene troncato |
| `DEBUG_HEXDUMP_MAX_BYTES` | limita l'hexdump nel journal quando esplicitamente abilitato |
| `MAX_CONCURRENT_SIDECARS` | limita parser e renderer post-archivio |
| `ALLOWED_CLIENTS` | IP esatti autorizzati; preferibile alla sola subnet |

`SPLIT_ON_ESCPOS_CUT=yes` è rifiutato: un pattern CUT può mancare, ripetersi o
apparire in un payload binario. I limiti vanno calibrati con traffico reale senza
ridurre `PRINTER_RESPONSE_TIMEOUT` sotto il massimo ritardo osservato.

Dopo una modifica:

```bash
sudo systemctl stop printproxy
sudo /usr/bin/python3 -I /opt/printproxy/printproxy.py \
  --config /etc/printproxy/printproxy.conf --check-config
sudo systemctl start printproxy
sudo printproxyctl self-test
```

## Artefatti per job

Con le opzioni di produzione mostrate sopra, ogni job genera quattro artefatti
di contenuto e un manifest JSON con la stessa base timestamp/UUID:

```text
<timestamp>_<jobid>.raw
<timestamp>_<jobid>.txt
<timestamp>_<jobid>.PULITO.txt
<timestamp>_<jobid>.pdf
<timestamp>_<jobid>.json
```

- `.raw`: copia autoritativa byte-identica del client.
- `.txt`: dump tecnico con comandi ESC/POS annotati.
- `.PULITO.txt`: vista umana ottenuta dal Document Model ESC/POS; le sequenze
  raster testuali vengono prima ricostruite e poi sottoposte a OCR bounded come
  fallback, conservando provenienza e confidenza.
- `.pdf`: ricevuta a larghezza configurabile, 80 mm di default e altezza
  variabile; incorpora i raster decodificati.
- `.json`: stato, endpoint, conteggi per direzione, FIN/RST, hash, risposta
  stampante catturata in modo limitato e risultato dei renderer.

`ENABLE_HEX_DUMP=yes` aggiunge deliberatamente un quinto sidecar diagnostico
`.hex`; per il set standard esatto deve restare `no`. Un errore di rendering non
blocca né trasforma la sessione TCP: viene registrato nel JSON. Il RAW resta
sempre la fonte forense.

Con più mapping, gli artefatti e il relativo ledger sono sotto
`jobs/<PRINTER_IP>/`; spool e lock sono sotto `spool/<PRINTER_IP>/`. Il registro
`manifest.jsonl` di ogni route usa hash chain e HMAC-SHA-256; la head è in
`manifest.head.json`. La chiave `/etc/printproxy/integrity.key` resta
`root:root 0600` e non viene rigenerata durante un upgrade.

Per vedere il formato dei quattro artefatti senza usare una stampante o dati
reali, il repository include un generatore sintetico:

```bash
python3 examples/generate_sample_receipt.py /tmp/printproxy-sample
```

L'esempio genera esclusivamente una ricevuta inventata destinata alla verifica
del renderer; non è una cattura della POS80BL reale.

## Verifica operativa

```bash
sudo printproxyctl self-test
sudo printproxyctl test-printer
systemctl --no-pager --full status printproxy
ss -H -ltn4 'sport = :9100'
journalctl -u printproxy -f
```

`self-test` e `test-printer` non stampano. La verifica completa richiede uno
snapshot stabile:

```bash
sudo systemctl stop printproxy
sudo printproxyctl verify
sudo systemctl start printproxy
```

La prova fisica è esplicita:

```bash
sudo printproxyctl test-print --proxy-id proxy-001 --confirm --text "TEST CORTESIA"
```

`test-print` apre una normale connessione locale alla VIP e non aggira ACL o
firewall. Se `ALLOWED_CLIENTS` autorizza soltanto il gestionale remoto, il
comando locale deve essere rifiutato. Eseguire allora la prova dal gestionale
autorizzato; in alternativa aggiungere temporaneamente la VIP interessata a
`ALLOWED_CLIENTS`, reinstallare/riavviare, fare il test e ripristinare subito
l'ACL. Non lasciare un'eccezione locale implicita.

Solo dopo un test autorizzato cambiare il gestionale da `10.1.2.200` a
`10.1.2.220`, mantenendo TCP/9100 RAW.

## Test automatici e limite hardware

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile \
  printproxy.py printproxy_core.py printproxyctl.py receipt_renderer.py
```

I test presenti coprono tre listener e tre fake printer concorrenti senza
cross-routing, isolamento di una stampante offline, relay binario nelle due
direzioni, DLE EOT, risposta
ritardata/frammentata, server-first, half-close, rifiuto del secondo client,
recovery senza replay, parser, bitmap, rendering, spool e integrità. Il dettaglio
è in [TEST_REPORT.md](docs/TEST_REPORT.md).

Non viene dichiarata compatibilità hardware POS80BL finché non è completata una
campagna reale direct-vs-proxy. Il modello POS80BL può differire dai riferimenti
Epson; status, ASB, tempi di chiusura e subset ESC/POS vanno misurati sul firmware
installato.

## Diagnostica e catture

La procedura tcpdump per confrontare collegamento diretto e proxy, con cautele
privacy, è in [TCP_PROXY.md](docs/TCP_PROXY.md). I dettagli ESC/POS sono in
[ESCPOS_PROTOCOL.md](docs/ESCPOS_PROTOCOL.md); AST e PDF in
[RECEIPT_RENDERING.md](docs/RECEIPT_RENDERING.md).

Per problemi rapidi:

```bash
journalctl -u printproxy -n 200 --no-pager
sudo printproxyctl status
sudo printproxyctl queue --all --json
```

Consultare [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) prima di ritentare un
job incerto.

## Rollback e rimozione

Il rollback funzionale è immediato: ripristinare nel gestionale
`10.1.2.200:9100`, quindi fermare Printproxy. Per rimuovere il software:

```bash
cd /srv/printproxy-src
sudo ./uninstall.sh
```

Per default configurazione, chiave, spool e archivi sono conservati. Le opzioni
di purge sono intenzionalmente esplicite e documentate in
[GIT_DEPLOYMENT.md](docs/GIT_DEPLOYMENT.md).

## Documentazione

- [ARCHITECTURE.md](docs/ARCHITECTURE.md): invarianti e stati.
- [CONFIGURATION.md](docs/CONFIGURATION.md): chiavi e validazione CSV.
- [MULTI_PRINTER.md](docs/MULTI_PRINTER.md): mapping, IP Debian e migrazione.
- [TCP_PROXY.md](docs/TCP_PROXY.md): state machine full-duplex e packet capture.
- [ESCPOS_PROTOCOL.md](docs/ESCPOS_PROTOCOL.md): status e parser ESC/POS.
- [RECEIPT_RENDERING.md](docs/RECEIPT_RENDERING.md): AST, testo pulito e PDF.
- [SECURITY.md](docs/SECURITY.md): minacce, privacy e integrità.
- [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md): diagnosi operativa.
- [TEST_REPORT.md](docs/TEST_REPORT.md): matrice dei test e gap hardware.
- [RECOVERY.md](docs/RECOVERY.md): recovery dell'archivio legacy.
