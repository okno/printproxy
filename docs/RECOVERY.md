# Recovery, incidenti e rollback

## Riavvio normale

```bash
sudo systemctl restart printproxy
sudo printproxyctl status
```

Per un audit completo: `stop` graceful, `sudo printproxyctl verify`, quindi `start`. `status` esegue online solo il controllo O(1) della head/HMAC.

Al boot:

- `RECEIVING`/`.tmp` diventa `PARTIAL`;
- `SEND_ARMED` diventa pre-send fallito e può essere ritentato;
- `SENDING` diventa `UNKNOWN_PRINT_STATE`;
- `QUEUED`/`FAILED_BEFORE_SEND` viene ricostruito nella coda;
- file/hash incoerenti diventano `QUARANTINED`.

## Stampante offline prolungata

La FIFO resta su disco. Con ordine preservato, il job più vecchio effettua backoff e i successivi attendono. Ripristinare rete/alimentazione e osservare:

```bash
journalctl -u printproxy -f
sudo printproxyctl queue
```

## Crash/power loss durante invio

Non riavviare manualmente gli unknown. Documentare:

- job ID e hash;
- intervallo temporale;
- byte affidati allo stack locale (solo metrica);
- presenza/assenza della stampa fisica;
- decisione e responsabile del retry.

Il comando con `--confirm-unknown` aggiunge un evento audit e reinserisce il job mantenendo la sequenza FIFO originale.

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

Nel gestionale:

```text
10.1.2.220:9100 -> 10.1.2.200:9100 RAW
```

Non è necessario modificare Debian. Verificare una stampa diretta. Quando la continuità è ristabilita, diagnosticare il proxy senza pressione operativa.

## Uninstall

```bash
sudo ./uninstall.sh
```

L’uninstall predefinito mantiene tutto ciò che serve a verificare lo storico. L’IP viene rimosso solo se `VIP_OWNED=yes`; un VIP preesistente non viene toccato. Se lo state installer manca, non indovinare manualmente: controllare `ip addr`, unit e nftables prima di rimuovere risorse.
