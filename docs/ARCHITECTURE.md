# Architettura e modello di affidabilità

## Decisione

Il proxy usa store-and-forward, non streaming simultaneo:

```text
receive chunked
  -> receiving/<uuid>.raw.tmp
  -> fsync periodico e finale
  -> rename/copia durevole nel DATA_DIR
  -> SHA-256 + sidecar + metadata
  -> evento hash-chain/HMAC
  -> QUEUED
  -> singolo worker
  -> stampante
```

L’ordine è più lento di un tee live, ma impedisce il caso “stampato e non archiviato”. La latenza aggiunta è la durata di ricezione più commit/sidecar; per normali ricevute è trascurabile rispetto al timeout di framing. Il parser leggibile gira in thread e non modifica né blocca il RAW già sigillato.

I buffer di rete e disco sono limitati da `CHUNK_SIZE`. L’intero RAW non è mantenuto in RAM durante ricezione o inoltro. Il `.txt` è best-effort, limitato da `MAX_READABLE_DUMP_BYTES` e generato con un semaforo dedicato.

## Perché non MITM ARP

Il gestionale può essere riconfigurato. ARP poisoning aggiungerebbe instabilità L2, rischio di intercettare traffico non pertinente, necessità di forwarding e rollback più fragile. Il listener dedicato fornisce una destinazione esplicita, ACL verificabili e nessuna modifica al routing globale.

## Framing RAW

TCP è uno stream: i confini dei pacchetti non hanno significato applicativo. RAW/9100 non definisce un job ID universale.

- FIN pulito è affidabile come fine connessione, non necessariamente fine scontrino.
- Idle è un’euristica: deve superare il massimo gap intra-job con margine.
- `GS V` CUT non è framing: può trovarsi in immagini, mancare o essere multiplo.
- In modalità persistente il servizio sigilla un segmento non vuoto e continua sulla stessa connessione.

L’invariante verificabile resta: la concatenazione ordinata dei RAW prodotti da una sessione equivale ai byte ricevuti, salvo un errore di storage esplicitamente marcato partial.

## Stato e commit

`RECEIVING` viene creato al primo chunk. Un crash lascia `.tmp` e state: al boot è sigillato come `PARTIAL`, mai inoltrato. Un `.tmp` orfano con UUID valido viene recuperato analogamente.

Prima dell’invio:

1. RAW, hash, metadata e ledger devono essere durevoli.
2. `SEND_ARMED` indica connessione in corso ma nessuna possibile `write()` ancora eseguita.
3. `SENDING` viene scritto/fsync prima della prima `writer.write()`.
4. Qualunque recovery da `SENDING` produce `UNKNOWN_PRINT_STATE`.

Una connect failure da `SEND_ARMED` è pre-send e ritentabile. Il backoff esponenziale è persistito. La sequenza FIFO iniziale è assegnata dall’evento `ARCHIVED`, autenticata nei metadata e non cambia durante i retry; con `PRESERVE_QUEUE_ORDER=yes` il job più vecchio offline trattiene i successivi per preservare l’ordine fisico.

Il ledger usa un append rapido con head/tail autenticata e firma del file per non bloccare l’event loop con una scansione crescente. Per questo DATA_DIR e SPOOL_DIR devono stare su storage Linux locale supportato (ext3/ext4, XFS, Btrfs o ZFS). La scansione crittografica completa di tutto il prefisso è deliberatamente una procedura offline con il daemon fermo.

## Significato di SENT_UNCONFIRMED

Il daemon ha letto tutto il RAW, chiamato `write()+drain()` per chunk e chiuso la sessione TCP senza eccezioni. Questo non è un ACK applicativo né un sensore carta. La stampante può aver perso alimentazione dopo aver ACKato TCP, avere carta esaurita o un buffer interno. Per questo lo stato non si chiama `PRINTED`.

## Concorrenza

Le ricezioni sono concorrenti e limitate dal semaforo. Sigillatura e ledger usano replace atomici e lock. Il forwarder è unico; la CLI deposita richieste nel filesystem e non invia. Non esiste quindi un percorso capace di interleavare job A e B sulla stessa connessione stampante.

## Protocolli diversi

LPR usa comandi, lunghezze e ACK; IPP usa HTTP e risposte. Un proxy one-way differito non conserva quella semantica. Il rilevamento si limita alle tre porte note, ma il deploy prosegue soltanto per RAW. L’eventuale variante LPR/IPP richiede un gateway protocol-aware, una diversa definizione del RAW archivistico e test dedicati.

## Failure matrix

| Punto | Stato finale | Inoltro/retry |
|---|---|---|
| RST client, max size/duration, SIGTERM in ricezione | `PARTIAL` | mai |
| ENOSPC prima del job | connessione rifiutata/reset | mai |
| ENOSPC durante il job | `PARTIAL` se persistibile | mai |
| connect rifiutata/timeout | `FAILED_BEFORE_SEND` | automatico con backoff |
| crash in `SEND_ARMED` | `FAILED_BEFORE_SEND` | sicuro |
| errore/crash in `SENDING` | `UNKNOWN_PRINT_STATE` | solo conferma manuale |
| invio e close locali completati | `SENT_UNCONFIRMED` | terminale |
| hash/file incoerente | `QUARANTINED` | mai |

## Assunzioni da validare sul sito

- POS80BL ascolta davvero RAW/9100.
- Il gestionale non richiede status duplex.
- 64 MiB sono sufficienti per il job massimo reale.
- Tre secondi eccedono ogni gap intra-job.
- DATA_DIR e SPOOL_DIR sono su filesystem Linux locale supportato; un UPS riduce i partial da power loss.
- Il gestionale rileva una chiusura/reset quando il proxy rifiuta per disco basso; RAW non offre comunque un ACK end-to-end.
