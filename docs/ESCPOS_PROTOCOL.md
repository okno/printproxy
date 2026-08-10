# ESC/POS: inoltro, status e parsing

## Due responsabilità separate

Printproxy tratta ESC/POS in due percorsi indipendenti:

1. **Relay TCP**: byte-opaco. Non decide se un comando è valido e non modifica
   mai il payload.
2. **Copia d'archivio**: parser best-effort e limitato che produce TXT tecnico,
   AST, testo pulito e PDF.

Un comando non supportato dal parser continua quindi a raggiungere la stampante
esattamente come ricevuto. Il `.raw` resta l'autorità forense.

## DLE EOT

Formato comune:

```text
ASCII: DLE EOT n
Hex:   10  04  n
```

Secondo il riferimento primario Epson
[DLE EOT](https://download4.epson.biz/sec_pubs/pos/reference_en/escpos/dle_eot.html),
il comando richiede uno status real-time; per i modelli non-peeler i valori
tipici `n=1..4` richiedono rispettivamente stato stampante, causa offline, causa
errore e sensore carta. Lo status tipico è un byte, ma modello e firmware
determinano valori e varianti.

Epson avverte inoltre di attendere lo status corrispondente prima di inviare
altro traffico, salvo il numero limitato di richieste continue previsto. È una
regola del protocollo tra gestionale e stampante: Printproxy non riordina, non
serializza semanticamente e non genera lo status.

Nel proxy:

```text
client  -- 10 04 n -->  printer
client  <-- byte reali -- printer
```

- la ricerca di DLE EOT attraversa i boundary dei chunk TCP;
- `realtime_status_queries` è solo un contatore diagnostico;
- `RealtimeStatusBlock` compare nell'AST della copia client;
- il reverse payload viene inoltrato tutto e ne vengono calcolati digest separati
  per ricevuto e consegnato;
- nessun valore, incluso `0x12`, è hardcoded come risposta.

Un byte di stato DLE EOT fotografa condizioni definite dal comando. Non dimostra
che l'intero scontrino sia stato stampato, tagliato o ritirato.

## Automatic Status Back

Il riferimento Epson
[GS a](https://download4.epson.biz/sec_pubs/pos/reference_en/escpos/gs_la.html)
descrive l'abilitazione di ASB (`1D 61 n`). Quando attivo, il dispositivo può
inviare uno status corrente all'abilitazione e nuovi status al cambiamento di
condizioni; il basic ASB Epson usa gruppi di quattro byte.

Conseguenze architetturali:

- una risposta può arrivare senza essere immediatamente preceduta da DLE EOT;
- la stampante può inviare più byte e più eventi nella stessa sessione;
- il reader inverso deve esistere per tutta la sessione, non solo dopo il CUT;
- non è corretto chiudere dopo il primo byte o trasformarlo in `OK`.

L'AST corrente non interpreta semanticamente `GS a`; lo registra come comando
sconosciuto/controllo best-effort. Il relay e il RAW non ne sono influenzati. Il
supporto POS80BL ad ASB e il formato effettivo richiedono una cattura hardware.

## Comandi riconosciuti dal Document Model

| Famiglia | Comandi | Rappresentazione |
|---|---|---|
| inizializzazione | `ESC @` | `InitializeBlock`, reset stile/codepage |
| stile | `ESC !`, `ESC E`, `ESC -`, `GS !` | bold, underline, larghezza, altezza, font |
| layout | `ESC a`, `ESC 3`, `ESC 2`, `ESC SP`, `ESC M` | alignment, spacing, font |
| avanzamento | LF, FF, `ESC d n`, `ESC J n` | `LineBreak`, `FeedBlock` linee/dot |
| codepage | `ESC t n` | cambio encoding noto; default `cp858` |
| bit image | `ESC * m nL nH ...` | raster 1-bit decodificato per colonne |
| raster | `GS v 0 m xL xH yL yH ...` | raster 1-bit row-major |
| barcode | `GS k` | `BarcodeBlock`, payload limitato |
| QR | sequenze `GS ( k` store/print | `QrCodeBlock` conservativo |
| taglio | `GS V`, `ESC i`, `ESC m` | `CutBlock` |
| cassetto | `ESC p` | `CashDrawerBlock` |
| real-time | `DLE EOT n`, `DLE ENQ n` | `RealtimeStatusBlock` |
| parametri barcode | `GS H`, `GS h`, `GS w`, `GS f` | state change tecnico |
| smoothing | `GS b` | state change tecnico |
| altro | ESC/GS/DLE/control sconosciuti | `UnknownCommandBlock` + warning |

Il TXT tecnico storico annota i principali comandi con tag `[ESC/POS ...]`. Il
testo pulito nasconde invece comandi, drawer, cut, status e unknown.

## Codepage

Il default di progetto è:

```ini
DEFAULT_CODEPAGE=cp858
```

CP858 preserva i caratteri occidentali e il simbolo euro. `ESC t 19` seleziona
esplicitamente CP858 nella tabella corrente. Sono mappate anche alcune codepage
comuni (CP437, CP850, CP860, CP863, CP865, CP1252, CP866, CP852, CP864, CP862,
CP1257 e CP775).

Una codepage `ESC t` non riconosciuta genera warning e mantiene la precedente.
Gli errori di decodifica sono sostituiti nel documento leggibile; i byte RAW non
sono mai sostituiti.

La tabella reale dei codepage dipende dal firmware e dalla configurazione della
stampante. Una stessa `n` non è universalmente portabile tra cloni ESC/POS.

## Bit image `ESC *`

Header:

```text
1B 2A m nL nH d...
```

Il parser gestisce le modalità classiche `m=0,1,32,33`:

- larghezza: `nL + 256*nH` colonne;
- altezza: 8 dot per `m=0,1`, 24 dot per `m=32,33`;
- payload: uno o tre byte verticali per colonna;
- output AST: bitmap 1-bit row-major, MSB-first.

Il PDF incorpora la bitmap decodificata. Più slice separate da feed conservano
spaziatura e ordine; il testo pulito le può rappresentare come un'unica regione
`[IMMAGINE]` quando sono consecutive.

## Raster `GS v 0`

Header:

```text
1D 76 30 m xL xH yL yH d...
```

La larghezza è `(xL + 256*xH) * 8` pixel, l'altezza è
`yL + 256*yH`. Le modalità normal/double-width/double-height/quadruple sono
riprodotte come fattori di scala nel PDF.

Dimensioni zero, payload troncati o immagini oltre i limiti non causano crash:
producono warning/unknown e il RAW resta disponibile.

## QR e barcode

Il parser è intenzionalmente conservativo:

- per `GS k` conserva symbology e payload dichiarato;
- per QR collega un comando store `GS ( k` al successivo print;
- un terminatore o payload mancante marca il nodo incompleto;
- i limiti impediscono allocazioni non controllate.

Il testo pulito usa `[CODICE A BARRE]` o `[QR CODE]`. Il PDF usa un riquadro con
etichetta e dettaglio sicuro: non promette che il simbolo ricreato sia
machine-scannable. Il RAW è necessario per replay forense e implementazioni
future protocol-aware.

## Feed, CUT e boundary

LF, `ESC d` e `ESC J` influenzano il documento. CUT e drawer sono registrati
nell'AST ma non stampati come testo nel PDF.

Il parser sa riconoscere CUT; il proxy non lo usa come unico delimitatore. Una
sequenza simile può comparire in dati binari, il comando può mancare o la
stampante può ricevere più CUT per sessione. Per questo
`SPLIT_ON_ESCPOS_CUT=yes` è rifiutato.

## Input sconosciuto e limiti

Il parser impone limiti su:

- byte di input;
- numero di nodi;
- caratteri decodificati;
- pixel e byte immagine;
- warning conservati;
- caratteri del testo pulito e altezza PDF.

Un comando sconosciuto conserva nel nodo una preview limitata e una motivazione;
la copia `.raw` separata conserva tutti i byte. Nessun contenuto viene eseguito.

## Limiti residui

- GS a/ASB è inoltrato ma non interpretato semanticamente nell'AST.
- Non tutte le tabelle codepage dei cloni POS80 sono note.
- QR/barcode PDF sono rappresentazioni conservative, non certificazioni di
  scansionabilità.
- Macro, NV graphics, downloaded bitmaps, page mode e comandi vendor-specific
  possono apparire come unknown.
- Il rendering fisico dipende da DPI, area stampabile e font del firmware.
- Non è stata completata una validazione hardware POS80BL direct-vs-proxy.
