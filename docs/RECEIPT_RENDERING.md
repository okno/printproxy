# Rendering delle ricevute

## Obiettivo

Il rendering è una funzione secondaria rispetto al proxy TCP. Deve produrre una
vista leggibile e una ricevuta PDF senza alterare o ritardare il relay live.

Per ogni job di produzione sono previsti:

```text
base.raw          payload client autoritativo
base.txt          dump tecnico ESC/POS
base.PULITO.txt   vista umana
base.pdf          ricevuta visuale
base.json         metadata, hash e risultato renderer
```

`ENABLE_HEX_DUMP=yes` aggiunge un sidecar diagnostico `.hex`; resta disabilitato
quando si richiede esattamente il set standard sopra.

## Un solo parser, due renderer

`receipt_renderer.py` espone l'API di integrazione:

```python
document = parse_escpos(raw, default_codepage="cp858")
clean = render_clean_text(document)
pdf_result = render_pdf(document, destination, best_effort=True)
```

oppure:

```python
result = render_receipt_artifacts(
    raw,
    clean_text_path=clean_path,
    pdf_path=pdf_path,
    default_codepage="cp858",
    pdf_width_mm=80,
)
```

La seconda funzione effettua il parsing una sola volta. TXT pulito e PDF
derivano dallo stesso `ReceiptDocument`; non esistono due interpretazioni
separate del flusso.

## Document Model

Il documento è una tupla immutabile di nodi tipizzati:

```text
ReceiptDocument
  +-- InitializeBlock
  +-- StateChangeBlock
  +-- TextBlock(text, TextStyle)
  +-- SeparatorBlock(pattern, TextStyle)
  +-- LineBreak
  +-- FeedBlock(lines, dots)
  +-- GraphicBlock
      +-- ImageBlock(width, height, packed_bits, density, alignment)
      +-- BarcodeBlock
      +-- QrCodeBlock
  +-- RasterTextBlock(text, source_bitmap, confidence, bounding_box)
  +-- CutBlock
  +-- CashDrawerBlock
  +-- RealtimeStatusBlock
  +-- UnknownCommandBlock
```

`GraphicBlock` è la base tipizzata dei nodi visivi e `SeparatorBlock` permette
di rappresentare una linea divisoria senza confonderla con un comando tecnico.
`TextStyle` conserva bold, underline, fattori width/height, alignment, font,
line spacing e character spacing. I cambi stile vengono applicati solo ai nodi
testo successivi.

Il documento registra inoltre dimensione originale, byte analizzati, flag di
troncamento, codepage predefinita e warning limitati.

## TXT tecnico

Il `.txt` storico resta destinato a diagnosi e reverse engineering. Mostra testo
decodificato e tag quali:

```text
[ESC/POS INIT]
[ESC/POS CHAR_SIZE 17]
[ESC/POS BOLD 1]
[ESC/POS BIT_IMAGE bytes=936]
[ESC/POS REALTIME 0x04 1]
```

Questo file non è la ricevuta umana e non sostituisce il RAW.

## PULITO.TXT

Il renderer pulito:

- esclude tag tecnici, cut, drawer, status e unknown;
- conserva testo, righe, feed e allineamento significativo;
- usa il testo di `RasterTextBlock` quando il raster ricostruito supera la
  soglia OCR, conservando `[IMMAGINE]` per una regione non riconosciuta;
- rappresenta QR e barcode con placeholder espliciti;
- decodifica CP858 e i cambi `ESC t` supportati;
- limita output e numero di righe vuote generate dai feed.

Esempio:

```text
Demo: 01/01/00  00:00

                Tavolo: 25-5

Sezione: A
--------------------------

1x Articolo dimostrativo

   Persone: 2
```

### Unwrap conservativo

Una stampante o il gestionale può spezzare un articolo così:

```text
1x Articolo d
   imostrativ
   o
```

Le righe vengono unite senza spazio soltanto quando tutti i segnali sono forti:

1. la prima riga inizia con un prefisso item riconoscibile, ad esempio `1x `;
2. la continuazione ha la stessa indentazione del prefisso;
3. inizia con lettera minuscola;
4. la riga originale precedente raggiunge quasi la larghezza fisica osservata;
5. non è un separatore, placeholder o riga vuota.

Il risultato è `1x Articolo dimostrativo`. Una riga indentata ambigua senza
questi segnali resta separata. L'euristica privilegia falsi negativi rispetto a
fusioni semanticamente errate.

## Bitmap

### ESC `*`

Le modalità 8-dot e 24-dot sono convertite da colonne verticali alla bitmap
1-bit row-major dell'AST. Densità orizzontale e verticale determinano la scala
fisica iniziale del PDF.

Una sequenza omogenea:

```text
ESC * band 1 -> ESC J 24/48 -> ESC * band 2 -> ...
```

viene ricostruita come un unico `ImageBlock`. Il feed interno è posizionamento
della testina/carta tra strip: `ESC *` non ha già fatto avanzare la carta. Il
vecchio renderer sommava sia l'altezza della bitmap sia il feed e separava le
strip con gap visibili.

### GS `v 0`

Il payload row-major viene mantenuto packed; normal, double-width,
double-height e quadruple impostano fattori di scala. L'immagine viene ridotta
proporzionalmente solo se supera l'area stampabile.

Il PDF costruisce in memoria un PNG monocromatico standard e lo passa a
ReportLab. Anche quando esiste un `RasterTextBlock`, usa sempre la sua
`source_bitmap`: l'OCR non sostituisce la grafica nel PDF.

Immagini incomplete vengono marcate `complete=false`; parti mancanti restano
bianche solo nella vista best-effort. Il RAW indica l'esatta incompletezza.

## OCR testuale bounded

L'OCR è un fallback semantico, non una correzione del layout:

```text
bitmap ESC/POS completa
  -> classificazione candidata testuale
  -> PGM con padding/upscale limitati
  -> tesseract ita+eng, TSV, timeout 5 s
  -> normalizzazione Unicode/righe
  -> confidence >= 70
  -> RasterTextBlock
```

Sono processate al massimo quattro immagini e quattro milioni di pixel. Il
subprocess non usa shell, riceve i pixel su stdin e produce un risultato
limitato. Nei log viene registrato `OCR_RASTER_TEXT` con numero blocchi,
confidence e bounding box, mai il testo della comanda. Se Tesseract, i dati
lingua o la confidenza mancano, l'`ImageBlock` resta immutato e il pulito mostra
`[IMMAGINE]`; RAW e PDF non falliscono.

Debian usa `tesseract-ocr` e `tesseract-ocr-ita`. La lingua di default è
`ita+eng`. `PRINTPROXY_OCR_LANG` è una variabile d'ambiente del processo, non
una chiave di `printproxy.conf`. Per un override persistente usare un drop-in:

```bash
sudo systemctl edit printproxy.service
```

```ini
[Service]
Environment="PRINTPROXY_OCR_LANG=ita+eng"
```

Quindi eseguire `sudo systemctl daemon-reload` e riavviare il servizio in una
finestra senza sessioni attive. Il valore deve riferirsi soltanto a language
pack Tesseract già installati e verificati con `tesseract --list-langs`.

## PDF termico

Impostazione predefinita:

```ini
SAVE_PDF=yes
PDF_WIDTH_MM=80
```

Caratteristiche:

- una pagina con larghezza 80 mm e altezza calcolata dal contenuto;
- margini 4 mm;
- font monospaced Courier/Courier-Bold;
- scaling separato per larghezza e altezza carattere;
- allineamento left/center/right;
- underline, character spacing e line spacing;
- feed in dot convertiti usando densità termica;
- immagini reali decodificate e non placeholder;
- QR/barcode conservativi in un riquadro etichettato;
- altezza massima e marker `[CONTENUTO TRONCATO]`.

Il PDF vuole essere semanticamente simile alla ricevuta, non una copia
metrologica della carta. Font, kerning, DPI e area stampabile POS80BL possono
differire dai valori Epson o da quelli stimati.

## QR e barcode

Il parser conserva symbology/payload quando la lunghezza è determinabile. Il PDF
non genera un simbolo che potrebbe sembrare valido ma codificare byte diversi:
usa un riquadro con tipo e dettaglio sicuro. Il risultato non è dichiarato
machine-scannable.

Per ottenere simboli scansionabili servirebbero supporto e test specifici per
ogni symbology, encoding e variante firmware, confrontati con il RAW.

## Isolamento dagli errori

ReportLab è importato solo quando viene richiesto il PDF. `best_effort=True`
trasforma dipendenza mancante, immagine anomala, errore font o I/O in un
`PdfRenderResult(success=false, error=...)` limitato. Non solleva l'errore nel
percorso di stampa.

La Definition of Done archivistica richiede comunque che tutti e quattro i
file standard esistano e abbiano hash validi. Un job con rendering fallito deve
essere segnalato nei metadata/monitoraggio e rigenerato offline dal RAW dopo aver
corretto la causa; non deve essere ristampato.

## Scrittura durevole

TXT pulito e PDF sono pubblicati così:

```text
crea temp esclusivo nella directory finale
  -> scrive/chiude
  -> fsync del file (PDF; il TXT fsynca il file aperto)
  -> chmod 0640 su POSIX
  -> os.replace(temp, finale)
  -> fsync della directory padre su POSIX
```

Il replace non segue un eventuale symlink finale. I nomi effettivi devono essere
derivati soltanto da timestamp/UUID interni e validati dal servizio.

## Limiti anti-abuso

`ParseLimits` limita per default:

| Risorsa | Limite |
|---|---:|
| input parser | 16 MiB |
| nodi AST | 100.000 |
| caratteri testo | 4.000.000 |
| pixel immagine | 8.000.000 |
| payload immagine | 8 MiB |
| warning | 64 |

Il servizio impone inoltre `MAX_JOB_BYTES`, `MAX_READABLE_DUMP_BYTES`,
`MAX_CONCURRENT_SIDECARS` e limiti su larghezza/altezza PDF. I limiti del parser
non riducono l'autorevolezza del `.raw` completo.

## Verifica del rendering

Per un campione autorizzato:

1. verificare SHA-256 del RAW;
2. confrontare `.PULITO.txt` con la carta;
3. usare `pdfinfo` per larghezza e altezza;
4. renderizzare il PDF a PNG con Poppler;
5. controllare immagini, clipping, overlap, accenti, euro e feed;
6. verificare che drawer, cut e status non compaiano come testo;
7. registrare firmware, DPI, carta e job ID.

```bash
pdfinfo job.pdf
pdftoppm -png -r 150 job.pdf /tmp/job-render
```

La verifica visuale di un PDF sintetico non dimostra equivalenza hardware. La
campagna POS80BL deve includere ricevute reali con bitmap 24-dot, raster, testo
double-size, CP858, QR/barcode, cut e DLE EOT.

### Regressione delle quattro bande

L'ispezione locale del PDF problematico mostrava quattro XObject lossless
`312x24`. Ogni banda era disegnata alta 9,6 pt, ma le ordinate differivano di
26,6247 pt: 9,6 pt di immagine più circa 17,024 pt, un pattern compatibile con
il doppio avanzamento osservato nella sequenza `BIT_IMAGE` / `FEED_DOTS 48`.
Ricomponendo i pixel senza contare nuovamente quel posizionamento si ottiene un
solo raster `312x96`, con rettangolo e testo completi. Il valore osservabile nel
PDF di produzione non viene trascritto nel repository pubblico e differiva
dalla stringa sintetica `25-5`; il RAW originale non era disponibile, quindi
l'associazione all'esatto comando ESC/POS resta un'inferenza e richiede una
nuova cattura RAW per essere confermata.

Il PDF di produzione e i suoi pixel non vengono pubblicati nel repository. I
test usano esclusivamente una fixture ESC/POS sintetica e priva di dati reali,
`Tavolo: 25-5`, con lo stesso schema quattro bande / tre feed. La fixture rende
riproducibili PDF e `.PULITO.txt`, ma non viene presentata come cattura POS80BL.

## Limiti noti

- OCR limitato a Tesseract e bitmap candidate; il fallback può restare
  `[IMMAGINE]` con grafica non testuale o confidenza insufficiente;
- nessuna garanzia di scansionabilità QR/barcode;
- unknown/vendor command non riprodotti visivamente;
- caratteri fuori WinAnsi possono diventare `?` nel font PDF built-in;
- page mode, macro e grafica NV non sono ancora renderizzati;
- nessuna validazione hardware POS80BL è dichiarata in questo repository.
