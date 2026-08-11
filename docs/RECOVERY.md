# Recovery, incidenti e rollback

## Riavvio normale

```bash
sudo systemctl restart printproxy
sudo printproxyctl status
```

Per un audit completo: `stop` graceful, `sudo printproxyctl verify`, quindi `start`. `status` esegue online solo il controllo O(1) della head/HMAC.

Al boot:

- `RECEIVING`/`.tmp` diventa `PARTIAL`;
- in `store_forward`, `SEND_ARMED` diventa pre-send fallito e può essere
  ritentato;
- in `store_forward`, `SENDING` diventa `UNKNOWN_PRINT_STATE` e
  `QUEUED`/`FAILED_BEFORE_SEND` viene ricostruito nella coda;
- in `transparent_duplex`, `DUPLEX_ACTIVE` diventa
  `UNKNOWN_PRINT_STATE` con `retry_allowed=false`: non viene mai reinserito in
  coda e non è ammesso replay;
- file/hash incoerenti diventano `QUARANTINED`.

## Stampante offline prolungata

Con `DELIVERY_MODE=store_forward` legacy, la FIFO resta su disco. Con ordine
preservato, il job più vecchio effettua backoff e i successivi attendono.
Ripristinare rete/alimentazione e osservare:

```bash
journalctl -u printproxy -f
sudo printproxyctl queue
```

Con `DELIVERY_MODE=transparent_duplex` non esiste una FIFO di replay: il proxy
apre la stampante prima di consumare il payload e segnala il fallimento TCP al
gestionale. Se una write era già possibile, lo stato resta incerto e non viene
ristampato. Dopo il controllo fisico e il ripristino della stampante, solo il
gestionale può iniziare consapevolmente una nuova sessione.

## Crash/power loss durante invio

Non riavviare o ritentare alla cieca gli unknown. Documentare:

- job ID e hash;
- intervallo temporale;
- byte affidati allo stack locale (solo metrica);
- presenza/assenza della stampa fisica;
- modalità di consegna, decisione operativa e responsabile.

Solo per un job legacy `store_forward` esplicitamente retryable, il comando con
`--confirm-unknown` aggiunge un evento audit e reinserisce il job mantenendo la
sequenza FIFO originale; resta una decisione manuale con rischio di duplicato
fisico.

Un job `transparent_duplex` ha `retry_allowed=false`: `printproxyctl retry`,
anche con `--confirm-unknown`, deve rifiutarlo. Il RAW duplex contiene una
conversazione interattiva e non può essere riprodotto come flusso unidirezionale.
Se serve una nuova stampa, deve essere il gestionale ad aprire una nuova sessione
dopo verifica fisica e decisione tracciata dell'operatore.

## Corruzione manifest o RAW

1. Fermare il servizio per congelare lo stato.
2. Non modificare o “riparare” manualmente gli originali.
3. Copiare archive, spool, `/etc/printproxy`, journal e backup su supporto protetto.
4. Eseguire `printproxyctl verify` sullo snapshot/copia con la key corretta.
5. Ripristinare solo da backup verificato e registrare l’incidente.

Un job quarantined non viene mai inoltrato automaticamente.

## Disco pieno

Il fail-closed impedisce nuovi inoltri non archiviati. Liberare spazio rimuovendo file non printproxy o espandendo il filesystem. Non cancellare il manifest/head/key. Per rimuovere archivi terminali usare retention approvata oppure una procedura che aggiunga tombstone; la cancellazione manuale verrà rilevata.

## Rollback funzionale immediato

Nel gestionale, ripristinare ogni mapping interessato:

```text
10.1.2.220:9100 -> 10.1.2.200:9100 RAW
10.1.2.221:9100 -> 10.1.2.201:9100 RAW
10.1.2.222:9100 -> 10.1.2.202:9100 RAW
```

Non è necessario modificare Debian. Verificare una stampa diretta. Quando la continuità è ristabilita, diagnosticare il proxy senza pressione operativa.

## Blocco lifecycle delle route

Se `install.sh` segnala `route lifecycle`, non sostituire endpoint e non
cancellare `/etc/printproxy/install-state`. Ripristinare temporaneamente tutte
le tuple registrate, quindi:

```bash
sudo systemctl stop printproxy
sudo printproxyctl verify
sudo printproxyctl queue --all
```

Su uno state precedente allo schema 3 il servizio deve restare fermo mentre
l’installer inferisce gli endpoint dagli state JSON. Prima dello schema 4 le
radici storage vengono recuperate una sola volta dal drop-in systemd già
installato; assenza, ambiguità o divergenza bloccano il rerun. Storia non vuota, state
corrotto/mancante, symlink, limite di scansione superato o tupla non più
presente producono un arresto fail-closed. Durante questo primo upgrade lasciare
`DATA_DIR` e `SPOOL_DIR` sulle radici storiche, perché lo state precedente non
registrava i percorsi. Conservare backup e HMAC key; per una
sostituzione intenzionale seguire la procedura “Rimozione o sostituzione di una
route” in [MULTI_PRINTER.md](MULTI_PRINTER.md).

## Uninstall

```bash
sudo ./uninstall.sh
```

L’uninstall predefinito mantiene tutto ciò che serve a verificare lo storico.
Ogni IP viene rimosso soltanto se la voce corrispondente di
`VIP_OWNED_LIST` è `yes`; un VIP preesistente non viene toccato. Lo state schema
3 fornisce anche `PRINTER_IP_LIST`/`PRINTER_PORT_LIST` per mostrare i rollback
corretti anche se la config è stata modificata. L’azione VIP `down` usa soltanto
VIP, ownership, prefisso e interfaccia registrati nello state: una lista
stampanti accorciata non può lasciare indirizzi posseduti. Lo state schema 1 con
`VIP_OWNED` singolo resta supportato. Se lo state installer manca, non indovinare
manualmente: controllare `ip addr`, unit e nftables prima di rimuovere risorse.
