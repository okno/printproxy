# Multi-stampante

## Regola di mapping

PrintProxy resta un solo processo systemd, ma crea una `ProxyInstance`
indipendente per ogni indice:

```text
LISTEN_IP[n]:LISTEN_PORT[n]
              |
              v
PRINTER_IP[n]:PRINTER_PORT[n]
```

La configurazione a tre stampanti:

```ini
LISTEN_IP=10.1.2.220,10.1.2.221,10.1.2.222
LISTEN_PORT=9100,9100,9100
PRINTER_IP=10.1.2.200,10.1.2.201,10.1.2.202
PRINTER_PORT=9100,9100,9100
```

inizializza, in ordine:

```text
proxy-001  listen 10.1.2.220:9100  printer 10.1.2.200:9100
proxy-002  listen 10.1.2.221:9100  printer 10.1.2.201:9100
proxy-003  listen 10.1.2.222:9100  printer 10.1.2.202:9100
```

`ProxyConfig` è immutabile e viene passato esplicitamente al child service. Non
esiste una destinazione stampante globale modificabile durante la sessione.

## Isolamento

Ogni route possiede separatamente:

- listener e task client;
- lock della propria stampante fisica;
- scheduler e worker (solo `store_forward`);
- state store, receiving spool e request queue;
- manifest/HMAC chain;
- limiti di sessione, errori e statistiche.

I tre listener usano lo stesso event loop senza busy-loop. Una stampante spenta
fa fallire/resetta soltanto le sessioni della sua route. Un errore storage o
integrità chiude quella route e produce `PROXY_INSTANCE_FAILED_ISOLATED`; le
altre continuano. Se tutte le route falliscono il processo termina non-zero per
consentire il restart systemd.

Il binding iniziale è transazionale: recovery di tutte le route, bind di tutti i
listener, poi avvio dei worker. Se il bind `n` fallisce, anche i listener già
aperti `0..n-1` vengono chiusi prima di restituire errore.

## Archivi

Con più route:

```text
/var/lib/printproxy/jobs/
|-- 10.1.2.200/
|-- 10.1.2.201/
`-- 10.1.2.202/

/var/lib/printproxy/spool/
|-- 10.1.2.200/
|-- 10.1.2.201/
`-- 10.1.2.202/
```

Il nome di entrambe le directory è l'IPv4 canonico e già validato della
stampante fisica; non proviene da un filename client e resta stabile anche se le
liste vengono riordinate. Ogni job conserva inoltre `proxy_id`, endpoint
listener e endpoint stampante nel metadata autenticato. Il log globale include
gli stessi campi su ogni evento.

## Preparare gli IP su Debian

Verificare prima la configurazione live:

```bash
ip -br -4 addr
ip -4 route get 10.1.2.200
ip -4 route get 10.1.2.201
ip -4 route get 10.1.2.202
```

Per un test temporaneo, dopo duplicate-address detection amministrativa:

```bash
sudo ip address add 10.1.2.220/24 dev enp1s0
sudo ip address add 10.1.2.221/24 dev enp1s0
sudo ip address add 10.1.2.222/24 dev enp1s0
```

In alternativa l'installer può farlo esplicitamente, senza toccare indirizzo
primario, gateway o route:

```bash
sudo ./install.sh --manage-vips
```

Per persistenza nativa preferire il gestore che possiede davvero l'interfaccia:

- NetworkManager: aggiungere gli indirizzi al profilo attivo con
  `nmcli connection modify <UUID> +ipv4.addresses 10.1.2.220/24` (ripetere) e
  usare `nmcli device reapply <IFACE>`;
- systemd-networkd: aggiungere `Address=10.1.2.220/24` (ripetere) in un drop-in
  del file `.network` effettivamente associato all'interfaccia;
- ifupdown: usare un hook dedicato `if-up.d`/`if-down.d`, non una seconda stanza
  `iface ... static` concorrente.

Non fare flap dell'interfaccia, `ip addr flush`, restart globale della rete o
riscrittura di gateway mentre si opera via SSH. Se manager/interfaccia sono
ambigui, fermarsi e risolvere prima la ownership di rete.

## Avvio e diagnostica

```bash
sudo /usr/bin/python3 -I /opt/printproxy/printproxy.py \
  --config /etc/printproxy/printproxy.conf --check-config
sudo systemctl restart printproxy
sudo printproxyctl status
sudo printproxyctl test-printer
sudo printproxyctl self-test
```

`status`, `test-printer` e `self-test` mostrano una sezione per route. Una
stampante `UNREACHABLE` non nasconde lo stato delle altre. Per una stampa fisica
in configurazione multi è obbligatorio scegliere esplicitamente:

```bash
sudo printproxyctl test-print --proxy-id proxy-002 --confirm
```

Verificare i listener realmente aperti sul server:

```bash
ss -lntp | grep ':9100'
```

e poi eseguire un pilot byte-per-byte per ogni percorso, inclusa una query DLE
EOT/risposta o ASB se il firmware la supporta. Un TCP connect vuoto è soltanto
un controllo listener e non crea un job.

## Migrazione da un mapping

1. Fermare nuovi job e verificare che non esistano backlog/UNKNOWN.
2. Eseguire `printproxyctl verify` a servizio fermo e fare backup di config,
   chiave e `/var/lib/printproxy`.
3. Estendere le quattro liste conservando integralmente la vecchia tupla; può
   essere riordinata, perché la directory resta legata al `PRINTER_IP`.
4. Configurare i nuovi IP oppure usare `install.sh --manage-vips`.
5. Validare, installare e collaudare tutte le route prima di modificare il
   gestionale.

Lo storico flat della vecchia route rimane intatto alla radice. I nuovi job
multi iniziano nelle directory per IP; non avviene una migrazione o nuova firma
silenziosa dei record precedenti.

## Rimozione o sostituzione di una route

Un normale rerun rifiuta la rimozione o la modifica di qualunque tupla già
registrata in `/etc/printproxy/install-state`. Anche una variazione della sola
porta è una sostituzione. Non cancellare lo state per aggirare il controllo.

Per una migrazione intenzionale:

1. fermare il servizio, congelare nuovi job ed eseguire `printproxyctl verify` e
   `printproxyctl queue --all`;
2. risolvere ogni stato replayable/UNKNOWN e creare un backup verificato di
   config, chiave, archive e spool;
3. mantenere il vecchio scope come archivio read-only e predisporre uno scope
   nuovo e vuoto, oppure eseguire la procedura di disinstallazione/purge
   esplicitamente approvata;
4. ripristinare la stessa chiave insieme allo storico che deve restare
   verificabile, quindi installare e collaudare la nuova tupla prima di cambiare
   il gestionale.

Il solo `uninstall.sh` conservativo mantiene state e storico e quindi non
costituisce, da solo, autorizzazione a riassociare lo spool flat.
