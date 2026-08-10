# Installazione Debian e collaudo

## Preflight umano

1. Confermare che `10.1.2.220` sia libero e riservarlo nel piano IP/DHCP.
2. Confermare che `10.1.2.200` sia la stampante e non cambi via DHCP.
3. Identificare l’IP esatto del gestionale e impostarlo in `ALLOWED_CLIENTS` se possibile.
4. Verificare RAW/9100 nella configurazione corrente del gestionale.
5. Pianificare una finestra di test e mantenere disponibile il rollback a `.200`.
6. Verificare che `/var/lib/printproxy` risieda su ext3/ext4, XFS, Btrfs o ZFS locale, con spazio monitorato e preferibilmente UPS.

## Installazione

```bash
scp -r printproxy amministratore@10.1.2.235:/tmp/
ssh amministratore@10.1.2.235
cd /tmp/printproxy
chmod +x install.sh uninstall.sh
sudo ./install.sh
```

L’installer è idempotente: preserva configurazione e chiave esistenti, aggiorna il codice e crea `.dist` quando i default sono cambiati. Ogni file sostituito viene copiato sotto `/var/backups/printproxy/<UTC>/`. Anche un rerun va eseguito in finestra di manutenzione senza nuovi job, perché il servizio viene arrestato/riavviato e una trasmissione già iniziata deve restare conservativamente incerta.

Non vengono eseguiti `ifdown`, restart del manager di rete, `ip addr flush`, `nft flush ruleset`, upgrade di sistema o rimozione pacchetti.

L’installer interrompe il deploy se DATA_DIR o SPOOL_DIR sono su NFS/CIFS, FUSE/DrvFS, overlay, `tmpfs` o altro filesystem non supportato: la durabilità di rename/fsync e il rilevamento live delle modifiche non sarebbero nel modello testato.

## Verifiche

```bash
sudo printproxyctl self-test
systemctl is-active printproxy printproxy-vip
systemd-analyze security printproxy.service
ss -lntp | grep '10.1.2.220:9100'
ip -o -4 addr show | grep '10.1.2.220/24'
ip route get 10.1.2.200
timedatectl status
```

La verifica completa richiede il daemon fermo per evitare una vista transiente di RAW, metadata e ledger:

```bash
sudo systemctl stop printproxy
sudo printproxyctl verify
sudo systemctl start printproxy
```

Un warning NTP impedisce di attribuire precisione affidabile ai timestamp ma non li trasforma mai in marca certificata.

## Acceptance `transparent_duplex`

Prima del pilot verificare che la configurazione effettiva contenga
`DELIVERY_MODE=transparent_duplex` e che non esista backlog legacy replayable.
Eseguire almeno 30 job rappresentativi, includendo obbligatoriamente il percorso
inverso stampante → gestionale, e verificare:

- un RAW per stampa attesa o la segmentazione prevista, identico byte per byte al
  flusso inviato dal gestionale;
- i quattro artefatti di cortesia per un job completo (`.raw`, `.txt`,
  `.PULITO.txt`, `.pdf`), il relativo JSON e tutti gli SHA-256 autenticati con la
  procedura offline `printproxyctl verify`;
- output fisico identico per ASCII, accenti, euro, raster, QR/barcode e taglio;
- una richiesta reale `DLE EOT n` supportata dal firmware: registrare il byte o
  i byte restituiti con collegamento diretto alla POS80BL, ripetere attraverso il
  proxy e confrontare i due flussi byte per byte; non imporre o simulare `0x12`;
- half-close client: dopo `shutdown(SHUT_WR)` il gestionale deve continuare a
  ricevere integralmente uno status ritardato o frammentato fino a FIN stampante
  o al timeout di tail configurato;
- eventuali byte ASB/server-first e il loro comportamento sul firmware reale;
- massimo gap intra-job e gap inter-job, compresi i segmenti su connessione
  persistente;
- esclusione tra sessioni concorrenti: il secondo client deve ricevere il
  fail-fast documentato e nessun byte dei due client deve essere interleavato;
- riavvio controllato senza sessioni live; un crash simulato dopo
  `DUPLEX_ACTIVE` deve produrre `UNKNOWN_PRINT_STATE` con
  `retry_allowed=false`, senza replay automatico o manuale;
- stampante offline: la sessione duplex deve fallire in modo osservabile al
  gestionale e non deve essere trasformata in un job FIFO da ristampare in
  seguito.

Il modello FIFO/offline/retry appartiene esclusivamente a
`DELIVERY_MODE=store_forward` legacy e non costituisce un test valido del
percorso duplex.

Se il gestionale apre una connessione per job, preferire:

```ini
JOB_END_MODE=connection_close
```

Se mantiene la connessione, conservare `hybrid` solo dopo aver misurato `IDLE_TIMEOUT`.

## Firewall

L’ACL applicativa è sempre attiva. Per una seconda barriera:

```ini
ALLOWED_CLIENTS=10.1.2.50
ALLOWED_NETWORKS=
ENABLE_FIREWALL=yes
```

Rieseguire `sudo ./install.sh`. Viene creata solo la tabella `inet printproxy_filter`, con match su destinazione VIP/porta. Nessuna policy globale o regola SSH viene toccata. Se la tabella esiste ma non è registrata come propria, l’installer si arresta.

## Cambio gestionale

Solo dopo il pilot:

```text
Destinazione precedente: 10.1.2.200:9100 RAW
Nuova destinazione:       10.1.2.220:9100 RAW
```

Non modificare driver, code page o formato ESC/POS nello stesso intervento: renderebbe difficile attribuire differenze al proxy.
