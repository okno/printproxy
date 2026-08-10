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
  +-- LineBreak
  +-- FeedBlock(lines, dots)
  +-- ImageBlock(width, height, packed_bits, density, alignment)
  +-- BarcodeBlock
  +-- QrCodeBlock
  +-- CutBlock
  +-- CashDrawerBlock
  +-- RealtimeStatusBlock
  +-- UnknownCommandBlock
```

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
- rappresenta raster consecutivi come `[IMMAGINE]`;
- rappresenta QR e barcode con placeholder espliciti;
- decodifica CP858 e i cambi `ESC t` supportati;
- limita output e numero di righe vuote generate dai feed.

Esempio:

```text
Operatore: 10/08/26  23:45

                [IMMAGINE]

Portata: 1
--------------------------

1x Acqua frizzante piccola

   Coperti: 1
```

### Unwrap conservativo

Una stampante o il gestionale può spezzare un articolo così:

```text
1x Acqua friz
   zante picc
   ola
```

Le righe vengono unite senza spazio soltanto quando tutti i segnali sono forti:

1. la prima riga inizia con un prefisso item riconoscibile, ad esempio `1x `;
2. la continuazione ha la stessa indentazione del prefisso;
3. inizia con lettera minuscola;
4. la riga originale precedente raggiunge quasi la larghezza fisica osservata;
5. non è un separatore, placeholder o riga vuota.

Il risultato è `1x Acqua frizzante piccola`. Una riga indentata ambigua senza
questi segnali resta separata. L'euristica privilegia falsi negativi rispetto a
fusioni semanticamente errate.

## Bitmap

### ESC `*`

Le modalità 8-dot e 24-dot sono convertite da colonne verticali alla bitmap
1-bit row-major dell'AST. Densità orizzontale e verticale determinano la scala
fisica iniziale del PDF.

### GS `v 0`

Il payload row-major viene mantenuto packed; normal, double-width,
double-height e quadruple impostano fattori di scala. L'immagine viene ridotta
proporzionalmente solo se supera l'area stampabile.

Il PDF costruisce in memoria un PNG monocromatico standard e lo passa a
ReportLab. Non usa OCR e non sostituisce il raster con il testo eventualmente
visibile nell'immagine.

Immagini incomplete vengono marcate `complete=false`; parti mancanti restano
bianche solo nella vista best-effort. Il RAW indica l'esatta incompletezza.

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

## Limiti noti

- nessun OCR delle immagini;
- nessuna garanzia di scansionabilità QR/barcode;
- unknown/vendor command non riprodotti visivamente;
- caratteri fuori WinAnsi possono diventare `?` nel font PDF built-in;
- page mode, macro e grafica NV non sono ancora renderizzati;
- nessuna validazione hardware POS80BL è dichiarata in questo repository.
