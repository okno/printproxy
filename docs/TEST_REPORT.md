# Test report

## Scopo

Questo documento distingue tre livelli:

1. test automatici presenti nel repository;
2. esecuzioni CI/locali da registrare per una release;
3. collaudo hardware POS80BL ancora da eseguire sul sito.

La presenza di un test non implica che una specifica release/tag abbia CI verde;
il record di esecuzione deve riportare commit, ambiente e risultato.

## Inventario dei test presenti

### `tests/test_duplex_proxy.py`

Test di integrazione con `FakeEscPosPrinter`:

- DLE EOT e risposta binaria inoltrati byte-exact live;
- risposta ritardata e frammentata dopo half-close client;
- risposta tardiva tra due segmenti attribuita al job precedente;
- quattro artefatti ricevuta più JSON/hash autenticati;
- byte server-first prima del payload client;
- richiesta grande e frammentata byte-exact;
- RST stampante dopo invio → `UNKNOWN_PRINT_STATE`, non ritentabile;
- `MAX_SESSION_DURATION` → reset e stato incerto;
- secondo client rifiutato mentre la stampante è occupata;
- startup duplex rifiutato con backlog store-forward replayable;
- race read/failure senza perdita dei byte già rimossi dal reader;
- recovery di `DUPLEX_ACTIVE` → unknown senza replay.

### `tests/fake_escpos_printer.py`

Emulatore TCP configurabile con:

- response unica o frammentata;
- ritardo di risposta e tra frammenti;
- soglia byte prima della risposta;
- dati server-first;
- FIN dopo risposta;
- RST dopo una soglia di ricezione;
- registrazione byte ricevuti e numero connessioni.

### `tests/test_receipt_renderer.py`

- INIT, bold, underline, size e alignment nell'AST;
- CP858, accenti ed euro;
- feed/linee/dot, cut, drawer, DLE real-time e unknown;
- bitmap ESC `*` 8/24-dot;
- raster GS `v 0`;
- QR store/print e barcode length-prefixed conservativi;
- input malformato, limiti e fuzz deterministico;
- `.PULITO.txt` senza marker tecnici;
- collapse slice immagine e unwrap conservativo;
- alignment/output bounded;
- PDF 80 mm ad altezza variabile con bitmap reale;
- API parse-once per clean/PDF;
- errore PDF restituito in modalità best-effort;
- fsync directory verificato tramite mock nell'API integrata.

### `tests/test_proxy.py`

Copertura legacy store-forward:

- RAW archiviato/inoltrato byte-exact;
- client concorrenti non interleaved;
- frammentazione TCP senza modifica RAW;
- failure ledger post-send mai classificato retry-safe;
- due boundary idle sulla stessa sessione;
- stampante offline, durabilità e retry pre-send.

### `tests/test_parser.py`

Parser tecnico storico:

- comandi comuni e cut;
- codepage e byte non gestito visibile;
- payload raster non scambiato per cut;
- varianti/troncamento cut;
- fuzz deterministico.

### `tests/test_hash.py`

- vettore SHA-256 noto;
- compatibilità byte dello schema metadata v1 durante upgrade duplex;
- chain/HMAC e tamper file;
- riordino manifest rilevato.

### `tests/test_spool.py`

- replace atomico dello state;
- move durevole byte-exact;
- lettura bounded di prefisso regular file con flag truncation;
- retention solo su stato terminale ammesso;
- rifiuto path traversal.

### `tests/test_failure_modes.py`

Copre metadata/head mancanti, chain malformata, tamper live, chiave HMAC binaria,
entrypoint isolato, state non-oggetto, recovery di SEALED/outbox, rollback state,
stato sconosciuto, state illeggibile, classificazione max duration e completezza
payload installazione.

### `tests/test_adversarial_failures.py`

Copre tamper metadata, rifiuto split CUT, verifica offline del prefisso, directory
e symlink al posto dei metadata, outbox autenticato alterato, retention forgiata,
failure ledger della richiesta retry e idempotenza del retry legacy.

## Mappatura ai criteri critici

| Criterio | Test automatico presente | Limite |
|---|---|---|
| client → printer byte-exact | sì, duplex e legacy | loopback/emulatore |
| printer → client byte-exact | sì | loopback/emulatore |
| status `0x12`/binario | sì, risposta include byte binari arbitrari | non prova valore POS80BL |
| response fragmentation | sì | timing sintetico |
| response delay 200 ms | sì | non misura massimo reale |
| client half-close | sì | stack OS del runner |
| server-first | sì | emulatore |
| secondo client fail-fast | sì | loopback |
| large/fragmented payload | sì, oltre 2 MiB nel test dedicato | non è soak test 64 MiB |
| crash recovery no replay | sì | crash state simulato |
| quattro artefatti + JSON | sì | campione sintetico |
| PDF con bitmap | sì | rendering software, non carta |
| hash sidecar/tamper | sì | threat root escluso |
| POS80BL reale | **no** | collaudo richiesto |
| direct-vs-proxy PCAP | **no** | rete/permesso richiesti |
| ASB reale | **no** | firmware richiesto |
| qualità taglio/carta | **no** | osservazione fisica richiesta |

## Comandi di test

Ambiente Python con ReportLab:

```bash
python3 -m pip install --disable-pip-version-check reportlab pillow
python3 -m py_compile \
  printproxy.py printproxy_core.py printproxyctl.py receipt_renderer.py
python3 -m unittest discover -s tests -v
```

Solo duplex:

```bash
python3 -m unittest -v tests.test_duplex_proxy
```

Solo renderer:

```bash
python3 -m unittest -v tests.test_receipt_renderer
```

Linux packaging:

```bash
python3 -I printproxy.py --config config/printproxy.conf --check-config
bash -n install.sh uninstall.sh network/printproxy-vip network/printproxy-firewall
shellcheck install.sh uninstall.sh network/printproxy-vip network/printproxy-firewall
```

La CI configurata esegue test su Ubuntu e Windows con Python 3.11 e 3.13, più
packaging Linux. Il risultato va letto dalla run associata al commit/tag; questo
documento non presume che una run non ancora eseguita sia verde.

## Esecuzione locale pre-commit osservata

Il working tree corrente è stato eseguito localmente l'11 agosto 2026 su Windows
con Python 3.14.5 e ReportLab installato:

```text
RUN=72 FAILURES=0 ERRORS=0 SKIPPED=1 OK=True
```

Lo skip riguarda la creazione di un symlink, non autorizzata dal token Windows
del processo (`WinError 1314`). Questo risultato è informativo e non sostituisce
la matrice CI del commit/tag finale né il collaudo hardware.

La stessa suite è stata eseguita anche sotto Linux/WSL con Python 3.13 e le
dipendenze di rendering installate:

```text
RUN=72 FAILURES=0 ERRORS=0 SKIPPED=0 OK=True
```

Il test di backpressure reverse usa intenzionalmente una finestra TCP minima e
può richiedere circa due minuti su filesystem virtualizzati; la deadline del
test è separata dai valori di produzione.

## Record di esecuzione release

Compilare dopo il freeze del commit:

| Campo | Valore |
|---|---|
| commit SHA | DA COMPILARE |
| tag | DA COMPILARE |
| data UTC | DA COMPILARE |
| Ubuntu / Python 3.11 | DA COMPILARE |
| Ubuntu / Python 3.13 | DA COMPILARE |
| Windows / Python 3.11 | DA COMPILARE |
| Windows / Python 3.13 | DA COMPILARE |
| packaging/shellcheck | DA COMPILARE |
| skip motivati | DA COMPILARE |
| link CI | DA COMPILARE |

Non sostituire `DA COMPILARE` con un risultato locale precedente al commit
finale.

## Collaudo hardware POS80BL richiesto

### Prerequisiti

- finestra autorizzata e rollback a `10.1.2.200` pronto;
- firmware/modello/seriale registrati;
- job sintetici privi di dati cliente;
- cattura diretta tramite endpoint o SPAN;
- cattura proxy sul Debian;
- orologi sincronizzati;
- operatore davanti alla stampante.

### Matrice minima

| ID | Scenario | Verifica |
|---|---|---|
| H01 | testo ASCII | contenuto e wrapping carta/PDF |
| H02 | CP858 accenti/euro | caratteri su carta, clean e PDF |
| H03 | bold/size/alignment | layout carta/PDF |
| H04 | ESC `*` 24-dot multi-slice | immagine e feed |
| H05 | GS `v 0` | raster reale |
| H06 | barcode | carta e payload RAW |
| H07 | QR | carta; PDF resta conservativo |
| H08 | cut/drawer | effetto fisico, nessun testo spurio |
| H09 | DLE EOT 1..4 supportati | byte risposta e timing direct/proxy |
| H10 | ASB `GS a` se supportato | server-first/eventi e 4-byte status |
| H11 | half-close client | risposta completa prima della chiusura |
| H12 | connessione persistente, due job | boundary archivio, upstream invariato |
| H13 | secondo client | RST fail-fast, nessun job ritardato |
| H14 | carta esaurita/coperchio aperto autorizzati | status reale; nessun falso ACK |
| H15 | printer RST/power interruption controllata | unknown e nessun replay |

### Confronto richiesto

Per ciascun caso confrontare:

- payload concatenato client → printer;
- payload concatenato printer → client;
- DLE EOT/ASB e ordine;
- delay risposta;
- FIN/RST/half-close;
- RAW SHA-256;
- presenza di `.raw`, `.txt`, `.PULITO.txt`, `.pdf`, `.json`;
- `render_status=complete` e hash sidecar;
- risultato applicativo del gestionale;
- carta reale e taglio.

La procedura PCAP e le cautele privacy sono in [TCP_PROXY.md](TCP_PROXY.md).

## Criteri di accettazione hardware

- [ ] Il gestionale completa il job senza rimanere in attesa.
- [ ] I byte forward e reverse sono uguali al collegamento diretto.
- [ ] Nessun ACK sintetico appare nella cattura.
- [ ] Il half-close non tronca lo status.
- [ ] Il secondo client è fail-fast e non stampa in ritardo.
- [ ] Il RAW è byte-identico.
- [ ] I quattro artefatti e il JSON esistono con hash validi.
- [ ] TXT pulito e PDF sono semanticamente coerenti con la carta.
- [ ] `SENT_UNCONFIRMED` non è presentato come conferma fisica.
- [ ] Nessun job duplex viene replayato dopo errore/crash.
- [ ] Privacy/retention delle catture sono rispettate.

## Stato attuale hardware

**Non validato in questo repository.** L'immagine di una ricevuta e un log
`SERVICE_START` non sostituiscono il confronto direct-vs-proxy, la cattura della
risposta e l'esito applicativo del gestionale. La firma hardware va compilata
solo dopo la matrice sopra.

| Campo | Valore |
|---|---|
| modello/firmware | DA COMPILARE |
| data/operatore | DA COMPILARE |
| PCAP direct SHA-256 | DA COMPILARE |
| PCAP proxy SHA-256 | DA COMPILARE |
| casi eseguiti | DA COMPILARE |
| anomalie | DA COMPILARE |
| esito go-live | DA COMPILARE |
