# Troubleshooting

## Raccolta iniziale

```bash
systemctl --no-pager --full status \
  printproxy printproxy-vip printproxy-firewall
journalctl -u printproxy -u printproxy-vip -b -n 300 --no-pager
grep -E '^(DELIVERY_MODE|LISTEN_|PRINTER_|JOB_END_MODE|IDLE_TIMEOUT|PRINTER_RESPONSE_TIMEOUT|FORWARD_TIMEOUT)=' \
  /etc/printproxy/printproxy.conf
ip -4 addr show
ip route get 10.1.2.200
ss -H -ltn4 'sport = :9100'
sudo printproxyctl status
sudo printproxyctl queue --all --json
```

Non incollare in ticket pubblici chiave HMAC, RAW, JSON completo, hexdump o PCAP:
possono contenere ricevute e dati personali.

## Il servizio non parte dopo l'upgrade

### `DELIVERY_MODE` mancante

L'installer rifiuta una configurazione storica priva della scelta esplicita.
Non copiare alla cieca il file `.dist`.

1. Fermare le stampe e creare backup.
2. Controllare gli stati legacy:

   ```bash
   sudo systemctl stop printproxy
   sudo printproxyctl queue --all --json
   ```

3. Se non esiste backlog replayable e si richiedono risposte stampante, aggiungere
   con `sudoedit /etc/printproxy/printproxy.conf`:

   ```ini
   DELIVERY_MODE=transparent_duplex
   ```

4. Validare e riavviare:

   ```bash
   sudo /usr/bin/python3 -I /srv/printproxy-src/printproxy.py \
     --config /etc/printproxy/printproxy.conf --check-config
   sudo systemctl start printproxy
   ```

Se esiste backlog legacy, smaltirlo prima con
`DELIVERY_MODE=store_forward`; l'avvio duplex lo rifiuta per evitare un replay
incompatibile con la nuova sessione live.

### VIP o bind mancanti

```bash
systemctl status printproxy-vip --no-pager -l
journalctl -u printproxy-vip -b --no-pager
ip route get 10.1.2.200
ip -4 addr show dev enp1s0
```

Il servizio non effettua fallback a `0.0.0.0`. Correggere route, conflitto DAD o
interfaccia e riavviare `printproxy-vip`, poi `printproxy`.

### ReportLab mancante

L'installer richiede `python3-reportlab`. Verificare:

```bash
/usr/bin/python3 -c 'import reportlab; print(reportlab.Version)'
dpkg -s python3-reportlab
```

Una dipendenza PDF mancante non deve alterare il relay, ma rende incompleto il
set obbligatorio di artefatti e compare come errore renderer.

## Il gestionale non si connette

```bash
ss -H -ltn4 'sport = :9100'
journalctl -u printproxy -f
nft list table inet printproxy_filter  # solo se ENABLE_FIREWALL=yes
```

Controllare VIP/porta nel gestionale, `ALLOWED_CLIENTS`, `ALLOWED_NETWORKS` e
route. `CLIENT_REJECTED` produce RST prima della creazione del job.

`test-printer` prova solo la reachability TCP upstream:

```bash
sudo printproxyctl test-printer
```

Non conferma DLE EOT, stampa o carta.

## Il secondo client riceve RST

Evento atteso:

```text
DUPLEX_REJECTED_BUSY
```

In `transparent_duplex` una sola sessione possiede la stampante. Il secondo
client è rifiutato immediatamente e non è messo in attesa. Verificare:

- connessioni parallele del gestionale;
- sessioni rimaste aperte senza FIN;
- `MAX_SESSION_DURATION` e `SESSION_IDLE_TIMEOUT`;
- eventuale client di monitoraggio che apre la stessa porta 9100.

Non aumentare `MAX_CONCURRENT_CLIENTS` come rimedio: non cambia l'esclusività
della stampante.

## La stampante stampa ma il gestionale resta in attesa

1. Verificare anzitutto la modalità:

   ```bash
   grep '^DELIVERY_MODE=' /etc/printproxy/printproxy.conf
   ```

   Deve essere `transparent_duplex`; `store_forward` non inoltra risposte.

2. Cercare gli eventi per sessione/job:

   ```bash
   journalctl -u printproxy --since '-10 min' --no-pager | \
     grep -E 'DUPLEX_|TCP_(FIN|RST|TIMEOUT)|LIVE_JOB|PRINTER_SESSION'
   ```

3. Nel JSON controllare:

   - `realtime_status_queries`;
   - `bytes_printer_received`;
   - `bytes_submitted_to_client`;
   - `bytes_printer_to_client`;
   - `printer_response_sha256`;
   - `printer_response_delivered_sha256`;
   - `client_fin_received` / `printer_fin_received`;
   - `client_close_kind` / `printer_close_kind`.

Interpretazione:

| Osservazione | Ipotesi |
|---|---|
| query DLE EOT > 0, byte printer = 0 | firmware non risponde, comando non supportato o timeout/chiusura troppo precoce |
| byte printer > 0, submitted client = 0 | client già chiuso o errore locale |
| submitted > delivered | drain client fallito durante la risposta |
| response hash ricevuto = delivered e conteggi uguali | proxy ha inoltrato i byte osservati; analizzare aspettativa applicativa |
| `TCP_TIMEOUT reason=response_idle` prima dello status | aumentare solo dopo misurazione `PRINTER_RESPONSE_TIMEOUT` |

Non aggiungere un ACK sintetico. Acquisire direct-vs-proxy come documentato in
[TCP_PROXY.md](TCP_PROXY.md).

## Half-close non termina o termina troppo presto

Il client FIN chiude soltanto client → stampante. Il reverse tail termina a FIN
stampante, silenzio `PRINTER_RESPONSE_TIMEOUT` o deadline `FORWARD_TIMEOUT`.

- Se la sessione resta aperta troppo: verificare ASB/keepalive o aumentare
  osservabilità; ridurre il timeout solo con cattura.
- Se lo status arriva dopo la chiusura: aumentare `PRINTER_RESPONSE_TIMEOUT`
  sopra il massimo ritardo misurato.
- Se il gestionale invia RST anziché half-close: il proxy non può consegnargli
  dati successivi; correggere timeout o comportamento del client.

## Stato `DUPLEX_ABORTED`

La sessione live non ha raggiunto una write stampante possibile. Il proxy non
esegue replay e mantiene `retry_allowed=false`; il gestionale ha ricevuto un
errore TCP e può aprire una nuova sessione secondo la propria logica.

Non creare manualmente richieste retry per job duplex.

## Stato `UNKNOWN_PRINT_STATE`

Una write verso la stampante era possibile prima del crash/RST/errore. Non si sa
quale prefisso sia stato stampato.

1. Non ritentare il RAW dal proxy.
2. Conservare RAW, JSON, manifest, state e log.
3. Verificare carta, buffer, spie e gestionale.
4. Correlare PCAP/log mediante session ID e job ID.

In `transparent_duplex`, anche un'opzione CLI di retry viene rifiutata perché
`retry_allowed=false`. La procedura `--confirm-unknown` riguarda soltanto stati
legacy replayable e non converte un job duplex in store-forward.

## Stato `SENT_UNCONFIRMED`

Indica relay/archivio completati senza errore osservato. Non è un ACK di stampa.
Uno status DLE EOT o ASB può indicare online/carta/errore in un istante, ma non è
una ricevuta universale del job. Non rinominare lo stato o impostare manualmente
`physical_print_confirmed=true`.

## Job `PARTIAL`

Controllare `boundary_reason`:

- `client_reset`: RST del gestionale;
- `max_job_bytes_exceeded`: superato `MAX_JOB_BYTES`;
- `max_job_duration_exceeded`: job troppo lungo;
- `max_session_duration_exceeded`: sessione oltre limite;
- `storage_error` / `storage_fsync_error`: filesystem, quota o ENOSPC;
- `service_shutdown` / `crash_*`: arresto durante ricezione/relay.

Un partial resta evidenza e non deve essere inviato manualmente alla stampante.

## File `.PULITO.txt` incompleto o errato

Il RAW resta autoritativo.

- controllare `DEFAULT_CODEPAGE=cp858` e gli `ESC t n` nel `.txt` tecnico;
- verificare warning/troncamento nel JSON;
- confrontare stile/immagini con la carta;
- non correggere il RAW;
- rigenerare offline il sidecar dopo aver corretto parser/configurazione.

Una fusione di righe avviene solo per item chiaramente wrapped. Se righe
distinte vengono unite, conservare il RAW di esempio e aggiungere un test prima
di modificare l'euristica.

## PDF mancante o malformato

Controllare:

```bash
grep -E '^(SAVE_PDF|PDF_WIDTH_MM|MAX_CONCURRENT_SIDECARS)=' \
  /etc/printproxy/printproxy.conf
pdfinfo /var/lib/printproxy/jobs/<job>.pdf
```

Nel JSON esaminare `render_status`, `sidecar_errors`, `pdf_filename` e
`pdf_sha256`. Un errore PDF non deve diventare errore di stampa; il set
archivistico resta però incompleto finché il PDF non viene rigenerato dal RAW.

QR/barcode nel PDF sono placeholder conservativi e non sono garantiti
scansionabili. Le bitmap ESC `*` e GS `v 0` devono invece apparire realmente.

## Risposta catturata troncata

`printer_response_truncated=true` significa che l'anteprima hex nel JSON ha
raggiunto `MAX_PRINTER_RESPONSE_CAPTURE_BYTES`. Non significa che il client
abbia ricevuto una risposta troncata. Usare conteggi e digest completi; aumentare
la capture solo dopo valutazione privacy e spazio.

## Debug hexdump

Abilitare temporaneamente:

```ini
DEBUG_HEXDUMP=yes
DEBUG_HEXDUMP_MAX_BYTES=256
```

Poi riavviare in finestra controllata e ripristinare `no`. Il journal può
contenere parti di ricevuta. Non usare hexdump come soluzione permanente e non
confonderlo con una PCAP completa.

## Integrità fallita

```bash
sudo systemctl stop printproxy
sudo printproxyctl verify
```

Non rigenerare la chiave, non riscrivere JSON/manifest e non rimuovere file.
Creare una copia in sola lettura di DATA_DIR, SPOOL_DIR, configurazione e chiave;
analizzare il primo errore. Riavviare soltanto dopo una procedura di recovery
approvata.

## Disco basso

Sotto `MIN_FREE_DISK_MB` nuovi job sono rifiutati. Non cancellare
`DUPLEX_ACTIVE`, `UNKNOWN_PRINT_STATE`, `PARTIAL` o `QUARANTINED`. Espandere il
volume o esportare artefatti terminali con hash verificati. La retention resta
disabilitata per default.

## Nessuna prova hardware ancora disponibile

Il fake printer dimostra la logica socket, non il comportamento POS80BL. Prima
del go-live raccogliere direct-vs-proxy con un job sintetico e documentare
firmware, risposta DLE EOT, ASB, delay, FIN/RST, bitmap e taglio.
