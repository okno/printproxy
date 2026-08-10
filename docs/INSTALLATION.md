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

## Pilot consigliato

Eseguire almeno 30 job rappresentativi e verificare:

- un RAW per stampa attesa o la segmentazione prevista;
- hash con la procedura offline `printproxyctl verify`;
- output fisico identico per ASCII, accenti, euro, raster, QR/barcode e taglio;
- nessun `DLE EOT`/status atteso dal gestionale;
- massimo gap intra-job e gap inter-job;
- riavvio controllato con coda vuota e con stampante offline.

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
