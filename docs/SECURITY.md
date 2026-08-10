# Sicurezza, audit e limiti probatori

## Minimo privilegio

Il daemon gira come `printproxy`, senza shell e senza capability. Il codice e `/etc` sono read-only nel namespace systemd; solo data, spool e log sono scrivibili. L’unit limita namespace, device, home, kernel, realtime, SUID e famiglie socket.

La gestione del VIP e del firewall resta in unit oneshot root separate. Il daemon non possiede `CAP_NET_ADMIN`.

## Input di rete

- bind esclusivo al VIP;
- ACL `ipaddress` prima della ricezione;
- numero client, durata e dimensione limitati;
- nessun contenuto di stampa nei log;
- nomi e percorsi mai derivati dal client;
- creazione esclusiva, no-follow e permessi `0640/0750`.

Preferire `ALLOWED_CLIENTS` con l’IP esatto. L’ACL IP non autentica crittograficamente il gestionale: una LAN ostile richiederebbe segmentazione, 802.1X/VLAN o un protocollo autenticato a monte; RAW non offre TLS nativo in questo modello.

## Integrità

Ogni record usa JSON UTF-8 canonico, sequence, event UUID, hash precedente e lunghezza a 64 bit prima del payload. La HMAC è confrontata constant-time. La head include contatore e hash finale autenticati.

I metadata sono mutabili come vista operativa, ma ogni transizione crea un evento immutabile con il loro hash corrente. `verify` controlla chain, HMAC, head, SHA/size RAW e hash metadata più recente.

Il percorso live evita una scansione O(n) a ogni evento: sotto lock valida head, tail autenticata e firma inode/dimensione/mtime/ctime del manifest. Questa difesa richiede un filesystem Linux locale con semantica affidabile; l’installer ammette ext3/ext4, XFS, Btrfs e ZFS e rifiuta storage di rete, FUSE/DrvFS, overlay e volatili. La procedura offline, a daemon fermo, rilegge invece l’intera chain e rileva anche una modifica del prefisso che non abbia toccato la tail.

La chiave non viene mai rigenerata in reinstall. Con `LoadCredential` il file root-only non viene reso group-readable. Se `ENABLE_HMAC=yes` e la key manca, il daemon fallisce: nessun downgrade silenzioso.

## Minacce non risolte localmente

- root può leggere RAM/credential e alterare servizio/storage;
- un amministratore capace di alterare anche i metadati inode o di sostituire coerentemente una snapshot supera il controllo live locale;
- snapshot rollback con manifest, head e key coerenti richiede ancoraggio esterno per essere provato;
- NTP e orologio locale non sono una TSA;
- TCP success non prova stampa fisica;
- RAW non autentica client o stampante;
- false boundary restano possibili senza framing applicativo.

Per audit forte: esportare giornalmente manifest/head su storage remoto immutabile, monitorare la head, separare ruoli amministrativi, usare UPS e centralizzare i journal. Per valore legale valutare TSA qualificata e requisiti privacy/retention con consulenza competente.

## Review operativa

- [ ] IP gestionale ristretto in ACL.
- [ ] VIP riservato e DAD superato.
- [ ] HMAC `root:root 0600` e backup offline protetto.
- [ ] NTP attivo e monitorato.
- [ ] filesystem locale supportato (preferibilmente ext4), UPS e capacity alert prima della soglia.
- [ ] finestra periodica: stop graceful, `verify` completo in sola lettura, restart e health check.
- [ ] backup cifrato di archive, manifest, config e key.
- [ ] policy definita per `UNKNOWN_PRINT_STATE`.
- [ ] retention approvata e default off confermato.
- [ ] recovery/reboot testati senza stampante reale o con finestra autorizzata.
- [ ] traffico pilot escluso da query duplex.
