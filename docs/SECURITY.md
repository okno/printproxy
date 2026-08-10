# Sicurezza, privacy e limiti probatori

## Modello di minaccia

Printproxy riceve dati binari non autenticati da una LAN e li inoltra a un
dispositivo fisico. Archivia inoltre ricevute potenzialmente contenenti dati
personali e commerciali. Gli obiettivi sono:

- non modificare i due flussi TCP;
- impedire interleaving tra client;
- conservare una copia RAW durevole prima dell'invio;
- rilevare alterazione locale di file e ordine degli eventi;
- contenere input, parser, log e renderer;
- evitare replay quando l'esito fisico è incerto.

Non rientrano nel modello: compromissione root/kernel, firmware stampante ostile,
autenticazione crittografica nativa di RAW/9100 e prova certificata di stampa
fisica.

## Minimo privilegio

Il daemon gira come utente `printproxy`, senza shell né capability. Systemd rende
codice e configurazione read-only e concede scrittura solo alle directory
dichiarate. Namespace, device, home, kernel, realtime, SUID e famiglie socket
sono limitati dall'unit.

VIP e firewall sono gestiti da unit oneshot root separate. Il daemon non possiede
`CAP_NET_ADMIN` e non abilita forwarding/NAT.

La chiave HMAC:

```text
/etc/printproxy/integrity.key  root:root 0600
```

è fornita al servizio tramite credenziale systemd. Un upgrade non la rigenera.
Se manca, il servizio fallisce senza downgrade silenzioso.

## Superficie TCP duplex

- bind esclusivo alla VIP, mai `0.0.0.0`;
- ACL IPv4 applicativa prima della lettura;
- nftables opzionale come difesa in profondità;
- massimo numero client, byte, durata job e durata sessione;
- timeout per connect, drain e reverse tail;
- lock esclusivo della stampante;
- secondo client resettato fail-fast, senza attesa differita;
- RST/errore propagato conservativamente;
- nessun ACK/status sintetico.

Un client autorizzato può aprire una sessione e non inviare dati, occupando per
`INITIAL_DATA_TIMEOUT` il lock stampante. Limitare `ALLOWED_CLIENTS` agli IP
esatti, monitorare `DUPLEX_SESSION_ACCEPTED` e calibrare il timeout senza rompere
client server-first o lenti.

L'ACL IP non autentica il gestionale. Su una LAN ostile servono segmentazione,
VLAN/802.1X, port security o un gateway autenticato a monte. RAW/9100 non offre
TLS in questa architettura.

## Trasparenza e comandi di stato

Il reverse stream è byte-opaco. Il proxy non interpreta uno status per
autorizzare un retry e non trasforma `DLE EOT` in un ACK di completamento. Questo
evita falsi positivi che potrebbero dichiarare stampato un job fallito.

Il contatore DLE EOT e la capture limitata sono osservabilità, non protocol
enforcement. ASB o dati proprietari sono inoltrati anche se il parser non li
comprende.

## Replay e duplicati

In `transparent_duplex` ogni job porta `retry_allowed=false`:

- prima di una write possibile: `DUPLEX_ABORTED`, il client osserva fallimento;
- dopo una write possibile: `UNKNOWN_PRINT_STATE`;
- completamento locale: `SENT_UNCONFIRMED`.

Il proxy non riproduce nessuno di questi RAW. Questo riduce duplicati generati
dal server, ma non impedisce al gestionale o a un operatore di iniziare una nuova
stampa. La decisione esterna deve considerare carta, stato applicativo e rischio
operativo.

La modalità legacy `store_forward` ha retry pre-send separati. Non deve essere
attiva per client che richiedono status. L'avvio duplex rifiuta backlog legacy
replayable per evitare commistioni.

## Input binario e resource exhaustion

Il relay usa chunk limitati e non carica l'intero RAW in RAM. I renderer hanno
limiti indipendenti su input, nodi, testo, pixel, payload immagine, warning,
altezza PDF e output. QR/barcode malformati, lunghezze raster enormi e comandi
sconosciuti producono warning/failure sidecar, non esecuzione di contenuto.

Controlli principali:

- `MAX_JOB_BYTES` e `MAX_JOB_DURATION`;
- `MAX_SESSION_DURATION`;
- `MAX_CONCURRENT_CLIENTS`;
- `MAX_CONCURRENT_SIDECARS`;
- `MAX_READABLE_DUMP_BYTES`;
- `MAX_PRINTER_RESPONSE_CAPTURE_BYTES`;
- `DEBUG_HEXDUMP_MAX_BYTES`;
- `MIN_FREE_DISK_MB` e riserva di emergenza.

Il relay della risposta non è troncato dalla capture. Se il client/stampante
produce un flusso senza fine, session duration e timeout sono l'ultima difesa.

## File e path

- timestamp e UUID sono generati internamente;
- nomi sidecar devono corrispondere esattamente al nome RAW atteso;
- path di configurazione devono essere assoluti, dedicati e non sovrapposti;
- componenti symlink e filesystem non supportati sono rifiutati;
- file sensibili usano `0640`, directory `0750`;
- creazione esclusiva e `O_NOFOLLOW` dove disponibile;
- write complete, file `fsync`, replace atomico e directory `fsync`;
- RAW/hash sono rivalidati prima di percorsi legacy di invio;
- un errore sidecar è registrato e non riscrive il RAW.

DATA_DIR e SPOOL_DIR devono risiedere su filesystem Linux locale supportato.
NFS/CIFS, FUSE/DrvFS, overlay e tmpfs non forniscono le assunzioni richieste di
fsync, inode e rename.

## Integrità e autenticità locale

Ogni evento usa JSON canonico, sequence, event UUID, previous hash e lunghezza.
La HMAC-SHA-256 è confrontata constant-time. La head autenticata conserva numero
record e chain hash finale.

`verify` controlla:

- chain, HMAC e head;
- schema/transizioni;
- SHA-256 e dimensione RAW;
- metadata più recenti;
- sidecar/hash registrati quando presenti.

Il percorso live valida head/tail e firma filesystem per evitare scansioni O(n)
durante ogni evento. La verifica completa richiede servizio fermo.

### Limiti probatori

- SHA-256 rileva modifica rispetto al digest, non l'autore della modifica.
- HMAC locale non resiste a root che possiede anche chiave e storage.
- Una snapshot coerente di manifest, head, archivi e key può essere ripristinata
  da un amministratore privilegiato senza ancoraggio esterno.
- L'orologio UTC/NTP locale non è una marca temporale qualificata.
- TCP/status non dimostrano stampa fisica.

Per audit forte esportare periodicamente head/manifest su storage remoto
append-only/WORM, separare ruoli e valutare TSA qualificata.

## Privacy di ricevute, log e PCAP

RAW, TXT, PULITO, PDF, JSON, `.hex`, journal debug e PCAP possono contenere:

- nomi/identificativi operatore;
- tavolo, camera o riferimento cliente;
- consumazioni, importi e orari;
- pattern di attività;
- comandi o token proprietari.

Misure operative:

- `DEBUG_HEXDUMP=no` e `ENABLE_HEX_DUMP=no` di default;
- catture con job sintetico e finestra minima;
- PCAP root-only, cifrato in transito e mai allegato pubblicamente;
- backup cifrati e accesso per ruolo;
- retention documentata secondo finalità e normativa applicabile;
- cancellazione verificata di copie di lavoro;
- centralizzazione log senza payload quando possibile.

`MAX_PRINTER_RESPONSE_CAPTURE_BYTES` riduce l'anteprima JSON ma non elimina il
rischio privacy: anche pochi byte possono essere sensibili.

## Retention

La retention automatica è disabilitata. Se abilitata, deve agire soltanto su
stati terminali eleggibili e dopo backup/verifica. Non cancellare
`DUPLEX_ACTIVE`, `UNKNOWN_PRINT_STATE`, `DUPLEX_ABORTED`, `PARTIAL` o
`QUARANTINED` durante un incidente.

La presenza dei quattro artefatti e del JSON deve essere verificata prima di
qualsiasi eliminazione. Un PDF fallito non autorizza ristampa del RAW.

## Packet capture autorizzata

La procedura direct-vs-proxy è in [TCP_PROXY.md](TCP_PROXY.md). Una cattura
diretta richiede un punto nel percorso o SPAN autorizzato; il server proxy non
può osservare una connessione che lo bypassa.

Prima della cattura definire responsabile, scopo, interfaccia, durata, luogo di
salvataggio, destinatari e cancellazione. Evitare `-i any` se non necessario.

## Hardening operativo

- [ ] `DELIVERY_MODE=transparent_duplex` esplicito e verificato.
- [ ] `ALLOWED_CLIENTS` ristretto al gestionale.
- [ ] VIP riservata e DAD superato.
- [ ] HMAC `root:root 0600`, backup offline protetto.
- [ ] NTP monitorato; limiti probatori compresi.
- [ ] filesystem locale supportato, UPS e alert spazio.
- [ ] hexdump/PCAP disabilitati fuori dalla finestra di diagnosi.
- [ ] `PRINTER_RESPONSE_TIMEOUT` misurato sul firmware reale.
- [ ] policy per RST busy e `UNKNOWN_PRINT_STATE` concordata.
- [ ] verifica completa periodica a servizio fermo.
- [ ] backup cifrato di archive, spool, config e key.
- [ ] retention e privacy approvate.
- [ ] test direct-vs-proxy POS80BL documentato.

## Gap hardware

I test automatici usano un emulatore TCP. Non provano sicurezza o conformità del
firmware POS80BL, corretta interpretazione di tutti i bit DLE EOT/ASB, tempi
reali, qualità del taglio o resistenza a input vendor-specific. Questi punti
restano requisiti di collaudo sul sito.
