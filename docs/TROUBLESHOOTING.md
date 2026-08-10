# Troubleshooting

## Il servizio non parte

```bash
systemctl status printproxy printproxy-vip --no-pager -l
journalctl -u printproxy -u printproxy-vip -b --no-pager
/usr/bin/python3 -I /opt/printproxy/printproxy.py \
  --config /etc/printproxy/printproxy.conf --check-config
ip route get 10.1.2.200
```

Il bind non effettua fallback a `0.0.0.0`. Se `.220` manca, correggere conflitto/route e riavviare `printproxy-vip`.

## Il gestionale non si connette

```bash
ss -lntp | grep 9100
ip -4 addr show
journalctl -u printproxy -f
nft list table inet printproxy_filter  # solo se abilitata
```

Controllare `ALLOWED_CLIENTS`/`ALLOWED_NETWORKS`, subnet e destinazione nel gestionale. Un client rifiutato viene chiuso prima di creare un job.

## La stampante è offline

```bash
sudo printproxyctl test-printer
sudo printproxyctl queue
ip route get 10.1.2.200
```

Gli stati `FAILED_BEFORE_SEND` sono ritentati automaticamente senza duplicati noti. Non usare `test-print` come prova di reachability: produce carta.

## UNKNOWN_PRINT_STATE

1. Non ritentare subito.
2. Verificare scontrino fisico, buffer/spie della stampante e log con job ID.
3. Se si accetta il rischio di duplicato:

```bash
printproxyctl retry UUID --confirm-unknown --reason "controllo fisico completato"
```

## Job partial

Controllare `boundary_reason` nel JSON:

- `client_reset`: il gestionale ha inviato RST;
- `max_job_bytes_exceeded`: aumentare solo dopo aver validato il job reale;
- `max_job_duration_exceeded`: slow client o timeout troppo basso;
- `storage_error`: filesystem/permessi/ENOSPC;
- `service_shutdown`/`crash_during_receive`: arresto durante la ricezione.

I partial non vanno copiati manualmente nella coda: possono essere incompleti.

## Integrità fallita

```bash
sudo systemctl stop printproxy
sudo printproxyctl verify
sudo systemctl start printproxy
sudo sha256sum /var/lib/printproxy/jobs/*.raw
ls -l /etc/printproxy/integrity.key
```

Non rigenerare la chiave e non riscrivere il manifest. Copiare in sola lettura l’intero `DATA_DIR`, `SPOOL_DIR`, configurazione e key; poi analizzare il primo errore. Una head più vecchia di un record HMAC valido può essere riparata automaticamente solo nella finestra di crash prevista; altre divergenze bloccano append/servizio.

## Disco basso

Il listener rifiuta nuovi job sotto `MIN_FREE_DISK_MB`. Una riserva locale consente di persistere diagnostica in caso di race ENOSPC. Non cancellare job `QUEUED`, `UNKNOWN`, `PARTIAL` o `QUARANTINED`. Espandere il volume oppure esportare job terminali con una procedura verificata; la retention automatica resta off per default.

## Il testo `.txt` è imperfetto

Il RAW rimane autoritativo. Impostare `DEFAULT_CODEPAGE` secondo la stampante e verificare eventuali `ESC t n`. Attivare temporaneamente `ENABLE_HEX_DUMP=yes` per la diagnostica. Parser e `.txt` non influenzano mai l’inoltro.
