# Installazione Debian e collaudo

## Preflight umano

1. Confermare che ogni VIP (`.220`, `.221`, `.222`) sia libera e riservarla nel
   piano IP/DHCP.
2. Confermare che ogni stampante fisica (`.200`, `.201`, `.202`) abbia IP fisso.
3. Identificare l’IP esatto del gestionale e impostarlo in `ALLOWED_CLIENTS` se possibile.
4. Verificare RAW/9100 nella configurazione corrente del gestionale.
5. Pianificare una finestra di test e mantenere disponibile il rollback a `.200`.
6. Verificare che `/var/lib/printproxy` risieda su ext3/ext4, XFS, Btrfs o ZFS locale, con spazio monitorato e preferibilmente UPS.

## Installazione

```bash
ssh amministratore@10.1.2.235
sudo apt-get update
sudo apt-get install --no-install-recommends -y git ca-certificates
sudo install -d -m 0755 -o "$(id -un)" -g "$(id -gn)" /srv/printproxy-src
git clone --origin origin https://github.com/okno/printproxy.git /srv/printproxy-src
cd /srv/printproxy-src
git fetch --tags --prune origin
git switch --detach <TAG_RELEASE_VERIFICATO>
git status --short
sudo ./install.sh --manage-vips
```

`git status --short` deve essere vuoto. Sostituire
`<TAG_RELEASE_VERIFICATO>` con il tag pubblicato e approvato; clone, aggiornamento,
rollback e rimozione della copia sorgente sono descritti in
[`GIT_DEPLOYMENT.md`](GIT_DEPLOYMENT.md). La copia con `scp` è soltanto
un'alternativa di sviluppo non verificabile come una release Git e non è il
percorso di deploy raccomandato.

Omettere `--manage-vips` quando tutti i `LISTEN_IP` sono già configurati dal
network manager. Senza autorizzazione esplicita, un indirizzo mancante provoca
un arresto diagnostico e nessuna modifica alla rete.

L’installer è idempotente: preserva configurazione e chiave esistenti, aggiorna
il codice e crea `.dist` quando i default sono cambiati. Ogni file sostituito
viene copiato sotto `/var/backups/printproxy/<UTC>/`. Anche un rerun va eseguito
in finestra di manutenzione senza nuovi job, perché il servizio viene
arrestato/riavviato e una trasmissione già iniziata deve restare
conservativamente incerta.

Lo state installer schema 4 registra la tupla completa di ogni route e le radici
canoniche `DATA_DIR`/`SPOOL_DIR`. Un rerun
può riordinare le tuple esistenti e aggiungerne di nuove, ma non può rimuovere o
sostituire listener, porta o destinazione di una tupla già installata. Il blocco
evita sia di abbandonare una directory per stampante sia di associare uno spool
flat storico a una stampante diversa. Anche cambiare una radice storage è
rifiutato senza una migrazione verificata. Per il primo upgrade da uno state più
vecchio è obbligatorio fermare `printproxy.service`: l’installer ricava gli
endpoint soltanto dagli state JSON regolari, senza symlink, con lettura e numero
di entry limitati. Se esiste storia ma la tupla non è ricavabile, l’installazione
si ferma e richiede una migrazione esplicita.

Prima che questo primo upgrade abbia scritto lo schema 4, non cambiare nello
stesso intervento `DATA_DIR` o `SPOOL_DIR`: lo state legacy non conteneva i
percorsi precedenti. L'installer recupera una sola volta le radici dal drop-in
systemd precedentemente installato e fallisce se tale identità manca o è
ambigua. Se i percorsi sono già stati modificati, ripristinarli, completare
upgrade e verifica, poi pianificare separatamente la migrazione storage.

Nel passaggio da un mapping flat a più mapping il servizio deve essere fermo e
l'installer usa la nuova codebase e la chiave HMAC esistente per verificare
offline l'intero ledger, i RAW, i metadata e la coerenza degli state prima di
valutarne lo stato terminale. Modificare soltanto uno state replayable per farlo
apparire terminale non autorizza quindi la migrazione; ogni errore richiede il
ripristino temporaneo della modalità singola e una risoluzione esplicita.

Non vengono eseguiti `ifdown`, restart del manager di rete, `ip addr flush`, `nft flush ruleset`, upgrade di sistema o rimozione pacchetti.

L’installer interrompe il deploy se DATA_DIR o SPOOL_DIR sono su NFS/CIFS, FUSE/DrvFS, overlay, `tmpfs` o altro filesystem non supportato: la durabilità di rename/fsync e il rilevamento live delle modifiche non sarebbero nel modello testato.

`VIRTUAL_PREFIX` deve inoltre coincidere esattamente con il prefisso IPv4
connesso presente sull’interfaccia. Per esempio una configurazione `/16` non è
accettata se l’interfaccia possiede la LAN di stampa come `/24`; l’installer non
deve creare accidentalmente una route connessa più ampia.

## Verifiche

```bash
sudo printproxyctl self-test
systemctl is-active printproxy printproxy-vip
systemd-analyze security printproxy.service
ss -lntp | grep ':9100'
ip -o -4 addr show | grep -E '10\.1\.2\.(220|221|222)/24'
for ip in 10.1.2.200 10.1.2.201 10.1.2.202; do ip route get "$ip"; done
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
- tre job contemporanei, uno per listener: ogni fake/physical printer deve
  ricevere soltanto i byte del proprio mapping; spegnere la seconda stampante
  non deve ritardare o fermare la prima e la terza;
- directory `jobs/10.1.2.200`, `jobs/10.1.2.201` e `jobs/10.1.2.202` separate,
  metadata e log con `proxy_id` ed endpoint corretti.

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

Rieseguire `sudo ./install.sh` (aggiungere `--manage-vips` solo se si autorizza
anche la creazione di nuovi indirizzi). Viene creata solo la tabella
`inet printproxy_filter`, con match separato su ogni destinazione VIP/porta.
Nessuna policy globale o regola SSH viene toccata. Se la tabella esiste ma non
è registrata come propria, l’installer si arresta.

La stampa fisica locale, quando autorizzata, si avvia esplicitamente con
`sudo printproxyctl test-print --proxy-id proxy-001 --confirm`. Il comando apre
una normale connessione locale alla VIP: non bypassa né l'ACL applicativa né la
tabella firewall. Se sono ammessi soltanto client remoti, il rifiuto del test
locale è quindi corretto; usare il gestionale autorizzato oppure aggiungere
temporaneamente, in una finestra controllata, la VIP della route a
`ALLOWED_CLIENTS`, reinstallare la configurazione e ripristinare subito l'ACL.

## Cambio gestionale

Solo dopo il pilot:

```text
Stampante 1: 10.1.2.200:9100 -> 10.1.2.220:9100 RAW
Stampante 2: 10.1.2.201:9100 -> 10.1.2.221:9100 RAW
Stampante 3: 10.1.2.202:9100 -> 10.1.2.222:9100 RAW
```

Non modificare driver, code page o formato ESC/POS nello stesso intervento: renderebbe difficile attribuire differenze al proxy.
