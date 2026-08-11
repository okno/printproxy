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
- ricomposizione lossless di quattro bande sintetiche `312x24` in un solo raster
  `312x96`, senza confondere immagini non correlate;
- fixture sintetica `Tavolo: 25-5`: PDF in-page non clippato e
  `.PULITO.txt` semantico senza `[IMMAGINE]`;
- OCR Tesseract bounded: confidence, fallback non fatale, backend reale sulla
  fixture sintetica quando il runtime è installato e nessun testo nei log.

### `tests/test_multi_config.py`

- configurazione legacy scalare con layout flat invariato;
- tre mapping CSV posizionali, trim e `ProxyConfig` immutabili;
- errore esplicito per lunghezze diverse, elementi vuoti, IPv4/porte invalidi;
- rifiuto listener e stampanti fisiche duplicate;
- directory DATA/SPOOL per IP fisico e stabilità dopo riordino delle liste.

### `tests/test_multi_proxy.py`

- tre listener e tre fake printer full-duplex attivi contemporaneamente;
- byte forward/reverse esatti, nessun cross-routing e archivi segregati;
- stampante offline senza fermare le route sane;
- errore storage route-local isolato dalle route sane;
- rollback atomico dei listener se un bind fallisce;
- compatibilità runtime single-route con layout flat;
- log OCR senza payload testuale e qualità conservata nei metadata;
- cinque artefatti (`RAW/TXT/PULITO/PDF/JSON`) segregati per ciascuna di tre
  route concorrenti;
- copia di stato/ledger HMAC valido fra scope fisici diversi rifiutata prima di
  qualsiasi connessione upstream.

### `tests/test_multi_ctl.py`

- `status`, `test-printer`, `self-test`, `verify` e `queue` su tutte le route;
- `test-print` richiede `--proxy-id` quando i mapping sono più di uno;
- retry seleziona un solo store, rifiuta ambiguità e transcript duplex;
- richiesta retry pubblicata atomicamente con UID/GID del daemon anche quando
  `printproxyctl` è eseguito tramite `sudo`, con difesa dal parent swap;
- storico flat legacy visibile e read-only, con errore su lavoro stranded;
- mismatch dell'endpoint fisico rilevato da `status`, `verify`, `queue` e
  `retry`.

### `tests/test_install_lifecycle.py`

- install-state schema 4 con tuple VIP/listener/stampante e identità canonica
  di `DATA_DIR`/`SPOOL_DIR`;
- riordino e aggiunta di route consentiti senza cambiare lo scope fisico;
- rimozione o sostituzione di route con storia esistente rifiutata;
- scansione legacy bounded, regular-file/no-symlink e servizio fermo;
- preparazione delle directory tramite dirfd/`O_NOFOLLOW`, incluso rifiuto di
  symlink nei figli dello spool senza modificare il bersaglio;
- prefisso VIP esattamente uguale alla subnet connessa;
- teardown VIP/firewall basato sullo state root-owned, non sulla config
  amministrativa mutabile.

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
- riordino manifest rilevato;
- binding HMAC del ledger allo scope fisico della stampante;
- verifica offline read-only senza creazione di `manifest.lock`.

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
| large/fragmented payload | sì, oltre 1 MiB nel test dedicato | non è soak test 64 MiB |
| crash recovery no replay | sì | crash state simulato |
| quattro artefatti + JSON | sì | campione sintetico |
| PDF con bitmap | sì | rendering software, non carta |
| bande ESC `*` ricomposte | sì, fixture sintetica quattro-bande | RAW originale non fornito |
| OCR testo raster | sì, engine iniettato e Tesseract reale su fixture sintetica | qualità POS80BL da collaudare |
| tre listener concorrenti | sì | loopback su tre IPv4 distinti |
| nessun cross-routing | sì, forward/reverse e directory | emulatore |
| fault isolation stampante | sì, offline e storage route-local | non è un test hardware |
| parser CSV/mapping | sì, inclusi errori e riordino | formato CSV soltanto |
| hash sidecar/tamper | sì | threat root escluso |
| POS80BL reale | **no** | collaudo richiesto |
| direct-vs-proxy PCAP | **no** | rete/permesso richiesti |
| ASB reale | **no** | firmware richiesto |
| qualità taglio/carta | **no** | osservazione fisica richiesta |

## Comandi di test

Ambiente Python con ReportLab:

```bash
python3 -m pip install --disable-pip-version-check reportlab pillow pypdf
python3 -m py_compile \
  printproxy.py printproxy_core.py printproxyctl.py receipt_renderer.py
python3 -m unittest discover -s tests -v
```

Solo duplex:

```bash
python3 -m unittest discover -s tests -p 'test_duplex_proxy.py' -v
```

Solo renderer:

```bash
python3 -m unittest discover -s tests -p 'test_receipt_renderer.py' -v
```

Solo multi-printer:

```bash
python3 -m unittest discover -s tests -p 'test_multi_*.py' -v
```

Linux packaging:

```bash
python3 -I printproxy.py --config config/printproxy.conf --check-config
bash -n install.sh uninstall.sh network/printproxy-vip network/printproxy-firewall
shellcheck install.sh uninstall.sh network/printproxy-vip network/printproxy-firewall
```

La CI configurata installa ReportLab/Pillow e, su Linux, Tesseract con la lingua
italiana. Esegue test su Ubuntu e Windows con Python 3.11 e 3.13, più packaging
Linux. Il risultato va letto dalla run associata al commit/tag; questo documento
non presume che una run non ancora eseguita sia verde.

## Esecuzione locale pre-commit osservata

Il working tree congelato è stato eseguito localmente l'11 agosto 2026 su
Windows con Python 3.14.5, ReportLab e pypdf:

```text
RUN=145 FAILURES=0 ERRORS=0 SKIPPED=5 OK=True
```

Gli skip Windows sono limitati a: creazione symlink senza privilegio
(`WinError 1314`), tre test POSIX di dirfd/setuid/no-follow e il test Tesseract
reale perché l'eseguibile non è installato su Windows.

La stessa snapshot è stata eseguita integralmente su Debian/WSL con Python
3.13.5, ReportLab, pypdf, Tesseract e dati lingua italiani:

```text
RUN=145 FAILURES=0 ERRORS=0 SKIPPED=0 OK=True
```

Questo secondo gate include il backend Tesseract reale e i test POSIX/root su
ownership, dirfd e symlink. Entrambi i risultati sono informativi e non
sostituiscono la matrice CI del commit/tag finale né il collaudo hardware. Il
test di backpressure reverse usa intenzionalmente una finestra TCP minima; la
deadline del test è separata dai valori di produzione.

## Record di esecuzione release

Prima matrice CI pubblica eseguita sul commit applicativo congelato:

| Campo | Valore |
|---|---|
| commit SHA | `d8572e25f82fe51b0eda63d5fc27e4a6c875414b` |
| tag | `v3.0.0` |
| data UTC | `2026-08-11T01:49:55Z` - `2026-08-11T01:50:59Z` |
| Ubuntu / Python 3.11 | 145 test, OK |
| Ubuntu / Python 3.13 | 145 test, OK |
| Windows / Python 3.11 | 145 test, OK, 4 skip di piattaforma |
| Windows / Python 3.13 | 145 test, OK, 4 skip di piattaforma |
| packaging/shellcheck | OK |
| skip motivati | Tesseract non installato su Windows; test dirfd/setuid POSIX |
| link CI | [GitHub Actions run 31450501917](https://github.com/okno/printproxy/actions/runs/31450501917) |

Il tag comprende esclusivamente questo commit applicativo e l'aggiornamento
documentale del relativo record CI. Il collaudo hardware resta separato e non è
implicato dall'esito della matrice software.

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
