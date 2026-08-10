# Architettura e modello di affidabilità

## Decisione principale

La modalità operativa raccomandata è esplicita:

```ini
DELIVERY_MODE=transparent_duplex
```

Printproxy mantiene una connessione client e una connessione stampante attive
contemporaneamente. Due coroutine indipendenti trattano i flussi:

```text
CLIENT_TO_PRINTER                         PRINTER_TO_CLIENT

client read                              printer read
    |                                        |
    +--> RAW temporaneo + fsync               +--> digest/capture limitata
    |                                        |
    +--> printer write/drain                  +--> client write/drain
```

Il payload non è decodificato nel percorso di relay. DLE EOT, ASB, ACK
proprietari, dati server-first e qualsiasi altro byte sono opachi. Parsing,
testo pulito e PDF lavorano su una copia archiviata dopo il percorso critico.

## Invarianti

1. Ogni byte client viene scritto su storage durevole prima di poter entrare nel
   send buffer del socket stampante.
2. Ogni byte letto dalla stampante viene inoltrato al client senza aggiunte,
   soppressioni o reinterpretazione.
3. Il limite della capture di risposta riguarda solo JSON/log; non limita il
   relay né il digest completo.
4. Non esiste una risposta sintetica: nessun `OK`, ACK `0x06` o status emulato.
5. Una sola sessione live possiede la stampante. Un secondo client viene
   resettato fail-fast, senza attesa e senza invio di suoi dati.
6. Un job duplex non è replayable. `retry_allowed=false` resta autenticato nei
   metadata e il worker legacy rifiuta qualsiasi tentativo.
7. `SENT_UNCONFIRMED` indica completamento del relay TCP osservato localmente,
   non conferma stampa fisica.
8. Un errore di parser, `.PULITO.txt` o PDF è un errore sidecar: non può cambiare
   i byte o l'esito della sessione TCP già conclusa.

## Apertura e proprietà della sessione

Il proxy apre l'upstream prima di consumare il payload client. Questo conserva
anche protocolli che inviano dati server-first. La proprietà esclusiva è
implementata con un lock per la singola stampante fisica:

```text
client A connect -> lock libero -> upstream aperto -> sessione attiva
client B connect -> lock occupato -> RST immediato
```

Il comportamento del client B non va descritto come una coda: nessun job B è
posticipato e nessun byte B deve essere stampato dopo la scadenza del gestionale.

`MAX_CONCURRENT_CLIENTS` limita le socket applicative, mentre l'esclusività della
stampante limita a uno il relay live effettivo.

## Durabilità prima dell'invio

Per ogni chunk client:

```text
read client
  -> write completo in receiving/<uuid>.raw.tmp
  -> fsync del file
  -> marker HMAC DUPLEX_ACTIVE prima della prima writer.write()
  -> write/drain verso stampante
```

Il costo di fsync è intenzionale: impedisce il caso in cui carta possa uscire ma
il corrispondente prefisso RAW non sia recuperabile. L'I/O bloccante è delegato a
un thread; la coroutine inversa resta schedulabile per ricevere status.

Alla frontiera del job, il RAW è pubblicato con move/rename durevole, riletto per
SHA-256, associato ai metadata e registrato nella hash chain/HMAC.

## State machine duplex

```text
RECEIVING
    |
    | primo invio armato, marker durevole prima di write()
    v
DUPLEX_ACTIVE
    |
    +--> archivio completo + relay completo ------> SENT_UNCONFIRMED
    |
    +--> write possibile + crash/errore ----------> UNKNOWN_PRINT_STATE
    |
    +--> recovery dopo DUPLEX_ACTIVE -------------> UNKNOWN_PRINT_STATE

nessuna write possibile + archivio disponibile ---> DUPLEX_ABORTED
input incompleto/limite/storage -------------------> PARTIAL o QUARANTINED
```

- `DUPLEX_ABORTED`: fallimento live prima di una write possibile;
  `retry_allowed=false`. È il gestionale, dopo l'errore TCP, a decidere una nuova
  sessione.
- `UNKNOWN_PRINT_STATE`: la stampante può aver ricevuto un prefisso o tutto;
  nessun replay, automatico o manuale, è ammesso in modalità duplex.
- `SENT_UNCONFIRMED`: tutti i byte del segmento sono stati archiviati e inoltrati
  senza errore osservato. `physical_print_confirmed=false` resta esplicito.
- `PARTIAL`: input non completo per policy o errore di storage; conservato come
  evidenza, non replayato.
- `QUARANTINED`: incoerenza di integrità o storage; richiede intervento.

La modalità legacy `store_forward` conserva la propria state machine
`QUEUED -> SEND_ARMED -> SENDING`, con retry sicuro solo prima di `SENDING`.
Questa state machine non deve essere proiettata sui job duplex.

## Half-close e chiusura

Quando il gestionale invia FIN sul proprio lato TX (`shutdown(SHUT_WR)`):

1. il proxy registra `client_fin_received` e `client_close_kind=fin`;
2. invia `write_eof()` verso la stampante quando supportato;
3. non chiude il reverse relay;
4. continua stampante → client fino a FIN stampante, errore/RST,
   `PRINTER_RESPONSE_TIMEOUT` senza attività o deadline totale
   `FORWARD_TIMEOUT`;
5. chiude poi socket e finalizza gli artefatti.

Il timeout del tail è necessario perché molte stampanti RAW non inviano FIN.
Deve essere superiore al massimo ritardo reale degli status. Non è una prova che
la stampa sia terminata.

Un FIN della stampante viene propagato al lato RX del client quando possibile.
Un RST/errore in una direzione resetta conservativamente l'altro lato e rende
l'esito incerto se una write era possibile.

## Sessioni persistenti e boundary d'archivio

TCP è uno stream; i pacchetti non sono job. Le policy accettate sono:

- `connection_close`: FIN client delimita il segmento;
- `idle_timeout`: un gap sigilla un segmento non vuoto;
- `hybrid`: il primo tra FIN e gap.

In duplex un idle boundary separa solo gli artefatti: la stessa connessione
upstream resta attiva per il segmento successivo. `SESSION_IDLE_TIMEOUT` limita
l'attesa tra segmenti; `MAX_SESSION_DURATION` limita l'intera sessione.

`SPLIT_ON_ESCPOS_CUT=yes` è rifiutato. Un semplice pattern `GS V` non è un
framing sicuro dentro un linguaggio con raster, barcode e comandi length-prefixed.

## Archiviazione e renderer

Il percorso standard produce:

```text
RAW byte-identico
  +--> TXT tecnico
  +--> Document Model ESC/POS
          +--> PULITO.TXT
          +--> PDF 80 mm ad altezza variabile
  +--> JSON metadata e hash
```

I renderer sono limitati da byte, nodi, caratteri, pixel e concorrenza. Scrivono
file temporanei nella directory di destinazione, fsyncano file e directory su
POSIX e pubblicano con replace atomico. ReportLab è caricato solo dal sidecar.
Il RAW non viene mai ricostruito dall'AST.

## Integrità

- SHA-256 verifica RAW e sidecar registrati.
- JSON canonico impedisce rappresentazioni ambigue.
- `manifest.jsonl` collega gli eventi con hash chain.
- HMAC-SHA-256 autentica eventi e head con una chiave root-only.
- `manifest.head.json` rileva truncation/rollback locale non coerente.
- `printproxyctl verify`, a daemon fermo, rilegge l'intera storia e ogni file.

DATA_DIR e SPOOL_DIR devono usare storage Linux locale con semantica di fsync e
rename affidabile. NFS/CIFS, FUSE/DrvFS, overlay e tmpfs sono esclusi dal modello
di durabilità.

## Failure matrix duplex

| Evento | Effetto client | Stato archivio | Replay proxy |
|---|---|---|---|
| upstream non apribile prima del payload | RST fail-fast | nessun job o `DUPLEX_ABORTED` se già iniziato | no |
| secondo client durante sessione attiva | RST fail-fast | nessun job del secondo client | no |
| client half-close, status ritardato | RX resta aperto entro timeout | `SENT_UNCONFIRMED` se completo | no |
| printer RST dopo possibile write | RST al client | `UNKNOWN_PRINT_STATE` | no |
| crash dopo marker `DUPLEX_ACTIVE` | sessione interrotta | recovery `UNKNOWN_PRINT_STATE` | no |
| ENOSPC/storage failure | RST/stop conservativo | `PARTIAL`/`QUARANTINED` | no |
| sidecar PDF fallisce | nessuna modifica al relay concluso | errore nel JSON | non applicabile |

## Modalità legacy e upgrade

Il parser di configurazione mantiene `store_forward` come default interno solo
per non cambiare in silenzio vecchi file, ma `install.sh` richiede che
`DELIVERY_MODE` sia presente. Prima di attivare duplex si deve verificare e
smaltire con la modalità legacy ogni backlog replayable. L'avvio duplex fallisce
se rileva stati legacy ancora inoltrabili.

## Assunzioni da validare sul sito

- POS80BL espone davvero RAW TCP/9100 e non LPR/IPP.
- Il firmware inoltra status DLE EOT/ASB sulla stessa connessione TCP.
- `PRINTER_RESPONSE_TIMEOUT` supera il massimo ritardo misurato.
- `IDLE_TIMEOUT` supera ogni gap intra-scontrino.
- Il gestionale gestisce correttamente un RST fail-fast se la stampante è già
  occupata.
- 64 MiB e 900 secondi coprono i job/sessioni legittimi.
- Una campagna direct-vs-proxy conferma FIN/RST, timing e byte osservabili.

Queste assunzioni non risultano validate su hardware POS80BL dal solo test
automatico con emulatore.
