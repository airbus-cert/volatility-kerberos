# volatility-kerberos
Volatility plugin to deal with windows kerberos security provider, list, carve and dump Tickets.

## Command `Sessions` : List kerberos sessions

The plugin is able to list sessions linked to the kerberos security provider, as `klist sessions` command.
It will also output the number of tickets available in the cache.

```
(volatility3) git clone https://github.com/airbus-cert/volatility-kerberos
(volatility3) python vol.py -p ./volatility-kerberos -s ./volatility-kerberos -f data.lime kerberos.Sessions
Volatility 3 Framework 2.27.1
Progress:  100.00               PDB scanning finished
Session Domain  TargetUsername  Nb Tickets

0:92461 SGA-AR-WIN-WKST$        attackrange.local       0
0:5f3f  SGA-AR-WIN-WKST$        attackrange.local       0
0:3e5                   0
0:3e4   sga-ar-win-wkst$        ATTACKRANGE.LOCAL       5
0:3e7   sga-ar-win-wkst$        ATTACKRANGE.LOCAL       6
0:b2c9  SGA-AR-WIN-WKST$        attackrange.local       0
0:5f6d  SGA-AR-WIN-WKST$        attackrange.local       0
0:b306  SGA-AR-WIN-WKST$        attackrange.local       0
0:962c5 DomainAdministrator     ATTACKRANGE.LOCAL       0
0:9302b SGA-AR-WIN-WKST$        attackrange.local       0
0:92f33 SGA-AR-WIN-WKST$        attackrange.local       0
0:9628c DomainAdministrator     ATTACKRANGE.LOCAL       0
0:eda0849       SA-MONITORING   ATTACKRANGE.LOCAL       2
0:ed9c775       SGA-AR-WIN-WKST$        attackrange.local       0
0:ed9c004       SGA-AR-WIN-WKST$        attackrange.local       0
0:ed9c7a6       SGA-AR-WIN-WKST$        attackrange.local       0
0:eda089a       SA-MONITORING   ATTACKRANGE.LOCAL       5
``` 

## Command `Tickets` : List kerberos cached tickets

The plugin is able to list all cached tickets.

```
(volatility3) git clone https://github.com/airbus-cert/volatility-kerberos
(volatility3) python vol.py -p ./volatility-kerberos -s ./volatility-kerberos -f data.lime kerberos.Tickets
Volatility 3 Framework 2.27.1
Progress:  100.00               PDB scanning finished
Address Client  Server  KerbTicket Encryption Type      Ticket Flags    Start Time      End Time        Renew Time      Session Key Type        Kdc Called

0x2af64e5c1f0   sga-ar-win-wkst$ @ ATTACKRANGE.LOCAL    cifs/sga-ar-win-dc.attackrange.local @ ATTACKRANGE.LOCAL        AES_256_CTS_HMAC_SHA_196        0x40a50000      2026-01-12 03:46:37+00:00       2026-01-12 13:31:37+00:00       2026-01-14 09:31:31+00:00       AES_256_CTS_HMAC_SHA_196      sga-ar-win-dc.attackrange.local
0x2af64dc0d10   sga-ar-win-wkst$ @ ATTACKRANGE.LOCAL    ldap/sga-ar-win-dc.attackrange.local/attackrange.local @ ATTACKRANGE.LOCAL      AES_256_CTS_HMAC_SHA_196        0x40a50000      2026-01-07 09:31:31+00:00       2026-01-07 19:31:31+00:00       2026-01-14 09:31:31+00:00     AES_256_CTS_HMAC_SHA_196        sga-ar-win-dc.attackrange.local
0x2af64dc0610   sga-ar-win-wkst$ @ ATTACKRANGE.LOCAL    GC/sga-ar-win-dc.attackrange.local/attackrange.local @ ATTACKRANGE.LOCAL        AES_256_CTS_HMAC_SHA_196        0x40a50000      2026-01-07 09:31:31+00:00       2026-01-07 19:31:31+00:00       2026-01-14 09:31:31+00:00     AES_256_CTS_HMAC_SHA_196        sga-ar-win-dc.attackrange.local
0x2af64e5bcb0   sga-ar-win-wkst$ @ ATTACKRANGE.LOCAL    krbtgt/ATTACKRANGE.LOCAL @ ATTACKRANGE.LOCAL    AES_256_CTS_HMAC_SHA_196        0x260a10000     2026-01-12 03:31:37+00:00       2026-01-12 13:31:37+00:00       2026-01-14 09:31:31+00:00       AES_256_CTS_HMAC_SHA_196      sga-ar-win-dc.attackrange.local
0x2af64e5b3f0   sga-ar-win-wkst$ @ ATTACKRANGE.LOCAL    krbtgt/ATTACKRANGE.LOCAL @ ATTACKRANGE.LOCAL    AES_256_CTS_HMAC_SHA_196        0x140e10000     2026-01-12 03:31:37+00:00       2026-01-12 13:31:37+00:00       2026-01-14 09:31:31+00:00       AES_256_CTS_HMAC_SHA_196      sga-ar-win-dc.attackrange.local
0x2af64e5c030   sga-ar-win-wkst$ @ ATTACKRANGE.LOCAL    cifs/sga-ar-win-dc.attackrange.local/attackrange.local @ ATTACKRANGE.LOCAL      AES_256_CTS_HMAC_SHA_196        0x40a50000      2026-01-12 08:18:27+00:00       2026-01-12 16:28:26+00:00       2026-01-14 09:31:31+00:00     AES_256_CTS_HMAC_SHA_196        sga-ar-win-dc.attackrange.local
0x2af64e5a970   sga-ar-win-wkst$ @ ATTACKRANGE.LOCAL    SGA-AR-WIN-WKST$ @ ATTACKRANGE.LOCAL    AES_256_CTS_HMAC_SHA_196        0x40a10000      2026-01-12 08:18:27+00:00       2026-01-12 16:28:26+00:00       2026-01-14 09:31:31+00:00       AES_256_CTS_HMAC_SHA_196     sga-ar-win-dc.attackrange.local
0x2af64e5c3b0   sga-ar-win-wkst$ @ ATTACKRANGE.LOCAL    ldap/sga-ar-win-dc.attackrange.local/ATTACKRANGE.LOCAL @ ATTACKRANGE.LOCAL      AES_256_CTS_HMAC_SHA_196        0x40a50000      2026-01-12 07:48:53+00:00       2026-01-12 16:28:26+00:00       2026-01-14 09:31:31+00:00     AES_256_CTS_HMAC_SHA_196        sga-ar-win-dc.attackrange.local
0x2af64dc0290   sga-ar-win-wkst$ @ ATTACKRANGE.LOCAL    LDAP/sga-ar-win-dc.attackrange.local @ ATTACKRANGE.LOCAL        AES_256_CTS_HMAC_SHA_196        0x40a50000      2026-01-07 09:31:31+00:00       2026-01-07 19:31:31+00:00       2026-01-14 09:31:31+00:00       AES_256_CTS_HMAC_SHA_196      sga-ar-win-dc.attackrange.local
0x2af64e5b070   sga-ar-win-wkst$ @ ATTACKRANGE.LOCAL    krbtgt/ATTACKRANGE.LOCAL @ ATTACKRANGE.LOCAL    AES_256_CTS_HMAC_SHA_196        0x260a10000     2026-01-12 06:28:26+00:00       2026-01-12 16:28:26+00:00       2026-01-14 09:31:31+00:00       AES_256_CTS_HMAC_SHA_196      sga-ar-win-dc.attackrange.local
0x2af64e5c570   sga-ar-win-wkst$ @ ATTACKRANGE.LOCAL    krbtgt/ATTACKRANGE.LOCAL @ ATTACKRANGE.LOCAL    AES_256_CTS_HMAC_SHA_196        0x140e10000     2026-01-12 06:28:26+00:00       2026-01-12 16:28:26+00:00       2026-01-14 09:31:31+00:00       AES_256_CTS_HMAC_SHA_196      sga-ar-win-dc.attackrange.local
0x2af64e5aeb0   SA-MONITORING @ ATTACKRANGE.LOCAL       LDAP/sga-ar-win-dc.attackrange.local/attackrange.local @ ATTACKRANGE.LOCAL      AES_256_CTS_HMAC_SHA_196        0x40a50000      2026-01-12 10:10:46+00:00       2026-01-12 20:10:41+00:00       2026-01-19 10:10:41+00:00     AES_256_CTS_HMAC_SHA_196        sga-ar-win-dc.attackrange.local
0x2af64dc0990   SA-MONITORING @ ATTACKRANGE.LOCAL       krbtgt/ATTACKRANGE.LOCAL @ ATTACKRANGE.LOCAL    AES_256_CTS_HMAC_SHA_196        0x140e10000     2026-01-12 10:10:41+00:00       2026-01-12 20:10:41+00:00       2026-01-19 10:10:41+00:00       AES_256_CTS_HMAC_SHA_196      sga-ar-win-dc.attackrange.local
0x2af64e5be70   SA-MONITORING @ ATTACKRANGE.LOCAL       ProtectedStorage/sga-ar-win-dc.attackrange.local @ ATTACKRANGE.LOCAL    AES_256_CTS_HMAC_SHA_196        0x40a50000      2026-01-12 10:10:47+00:00       2026-01-12 20:10:41+00:00       2026-01-19 10:10:41+00:00    AES_256_CTS_HMAC_SHA_196 sga-ar-win-dc.attackrange.local
0x2af64e5b230   SA-MONITORING @ ATTACKRANGE.LOCAL       cifs/sga-ar-win-dc.attackrange.local @ ATTACKRANGE.LOCAL        AES_256_CTS_HMAC_SHA_196        0x40a50000      2026-01-12 10:10:47+00:00       2026-01-12 20:10:41+00:00       2026-01-19 10:10:41+00:00       AES_256_CTS_HMAC_SHA_196      sga-ar-win-dc.attackrange.local
0x2af64dc0b50   SA-MONITORING @ ATTACKRANGE.LOCAL       LDAP/sga-ar-win-dc.attackrange.local/attackrange.local @ ATTACKRANGE.LOCAL      AES_256_CTS_HMAC_SHA_196        0x40a50000      2026-01-12 10:10:41+00:00       2026-01-12 20:10:41+00:00       2026-01-19 10:10:41+00:00     AES_256_CTS_HMAC_SHA_196        sga-ar-win-dc.attackrange.local
0x2af64e5b930   SA-MONITORING @ ATTACKRANGE.LOCAL       krbtgt/ATTACKRANGE.LOCAL @ ATTACKRANGE.LOCAL    AES_256_CTS_HMAC_SHA_196        0x260a10000     2026-01-12 10:10:47+00:00       2026-01-12 20:10:41+00:00       2026-01-19 10:10:41+00:00       AES_256_CTS_HMAC_SHA_196      sga-ar-win-dc.attackrange.local
0x2af64dc0450   SA-MONITORING @ ATTACKRANGE.LOCAL       krbtgt/ATTACKRANGE.LOCAL @ ATTACKRANGE.LOCAL    AES_256_CTS_HMAC_SHA_196        0x140e10000     2026-01-12 10:10:41+00:00       2026-01-12 20:10:41+00:00       2026-01-19 10:10:41+00:00       AES_256_CTS_HMAC_SHA_196      sga-ar-win-dc.attackrange.local
```

## Command `Dump`: ticket in kirbi format

The plugin is able to dump any ticket into kirbi format. It requiures install `impacket` in the same python environment than volatility.

```
(volatility3) pip install impacket
```

Then by specifying the virtual address of the ticket the plugin will be able to dump into the specified output folder:

```
(volatility3) git clone https://github.com/airbus-cert/volatility-kerberos
(volatility3) python vol.py -p ./volatility-kerberos -s ./volatility-kerberos -f data.lime kerberos.Dump --address 0x2af64e5b930 --output c:\work\tmp
Volatility 3 Framework 2.27.1
Progress:  100.00               PDB scanning finished
Output

c:\work\tmp\0x2af64e5b930.kirbi
```

## Command `VadTicketScan` : Carve Tickets 

The plugin is also able to carve ticket by checking predictable value into the kerberos ticket structure layout.
The plugin will try to find memory layout that match the offset of `ticket.tkt_vno==5` and `ticket.EType in [1, 3, 17, 18, 23, 24]`.

```
(volatility3) git clone https://github.com/airbus-cert/volatility-kerberos
(volatility3)  python vol.py -p ./volatility-kerberos -s ./volatility-kerberos -f data.lime kerberos.VadTicketScan
Volatility 3 Framework 2.27.1
Progress:  100.00               PDB scanning finished
Address Client  Server  KerbTicket Encryption Type      Ticket Flags    Start Time      End Time        Renew Time      Session Key Type        Kdc Called

0x2af64dc0290   SGA-AR-WIN-WKST$        LDAP/sga-ar-win-dc.attackrange.local    AES_256_CTS_HMAC_SHA_196        0x40a50000      2026-01-07 09:31:31+00:00       2026-01-07 19:31:31+00:00       2026-01-14 09:31:31+00:00       AES_256_CTS_HMAC_SHA_196        sga-ar-win-dc.attackrange.local
0x2af64dc0450   SA-MONITORING   krbtgt/ATTACKRANGE.LOCAL        AES_256_CTS_HMAC_SHA_196        0x140e10000     2026-01-12 10:10:41+00:00       2026-01-12 20:10:41+00:00       2026-01-19 10:10:41+00:00       AES_256_CTS_HMAC_SHA_196        sga-ar-win-dc.attackrange.local
0x2af64dc0610   UNKNOWN GC/sga-ar-win-dc.attackrange.local/attackrange.local    AES_256_CTS_HMAC_SHA_196        0x0     2026-01-07 09:31:31+00:00       2026-01-07 19:31:31+00:00       2026-01-14 09:31:31+00:00       AES_256_CTS_HMAC_SHA_196        sga-ar-win-dc.attackrange.local
0x2af64dc0990   UNKNOWN krbtgt/ATTACKRANGE.LOCAL        AES_256_CTS_HMAC_SHA_196        0x0     2026-01-12 10:10:41+00:00       2026-01-12 20:10:41+00:00       2026-01-19 10:10:41+00:00       AES_256_CTS_HMAC_SHA_196        sga-ar-win-dc.attackrange.local
0x2af64dc0b50   SA-MONITORING   LDAP/sga-ar-win-dc.attackrange.local/attackrange.local  AES_256_CTS_HMAC_SHA_196        0x40a50000      2026-01-12 10:10:41+00:00       2026-01-12 20:10:41+00:00       2026-01-19 10:10:41+00:00       AES_256_CTS_HMAC_SHA_196        sga-ar-win-dc.attackrange.local
0x2af64dc0d10   SGA-AR-WIN-WKST$        ldap/sga-ar-win-dc.attackrange.local/attackrange.local  AES_256_CTS_HMAC_SHA_196        0x40a50000      2026-01-07 09:31:31+00:00       2026-01-07 19:31:31+00:00       2026-01-14 09:31:31+00:00       AES_256_CTS_HMAC_SHA_196     sga-ar-win-dc.attackrange.local
0x2af64e5a970   SGA-AR-WIN-WKST$        SGA-AR-WIN-WKST$        AES_256_CTS_HMAC_SHA_196        0x40a10000      2026-01-12 08:18:27+00:00       2026-01-12 16:28:26+00:00       2026-01-14 09:31:31+00:00       AES_256_CTS_HMAC_SHA_196        sga-ar-win-dc.attackrange.local
0x2af64e5aeb0   UNKNOWN LDAP/sga-ar-win-dc.attackrange.local/attackrange.local  AES_256_CTS_HMAC_SHA_196        0x0     2026-01-12 10:10:46+00:00       2026-01-12 20:10:41+00:00       2026-01-19 10:10:41+00:00       AES_256_CTS_HMAC_SHA_196        sga-ar-win-dc.attackrange.local
0x2af64e5b070   SGA-AR-WIN-WKST$        krbtgt/ATTACKRANGE.LOCAL        AES_256_CTS_HMAC_SHA_196        0x260a10000     2026-01-12 06:28:26+00:00       2026-01-12 16:28:26+00:00       2026-01-14 09:31:31+00:00       AES_256_CTS_HMAC_SHA_196        sga-ar-win-dc.attackrange.local
0x2af64e5b230   SA-MONITORING   cifs/sga-ar-win-dc.attackrange.local    AES_256_CTS_HMAC_SHA_196        0x40a50000      2026-01-12 10:10:47+00:00       2026-01-12 20:10:41+00:00       2026-01-19 10:10:41+00:00       AES_256_CTS_HMAC_SHA_196        sga-ar-win-dc.attackrange.local
0x2af64e5b3f0   SGA-AR-WIN-WKST$        krbtgt/ATTACKRANGE.LOCAL        AES_256_CTS_HMAC_SHA_196        0x140e10000     2026-01-12 03:31:37+00:00       2026-01-12 13:31:37+00:00       2026-01-14 09:31:31+00:00       AES_256_CTS_HMAC_SHA_196        sga-ar-win-dc.attackrange.local
0x2af64e5b930   SA-MONITORING   krbtgt/ATTACKRANGE.LOCAL        AES_256_CTS_HMAC_SHA_196        0x260a10000     2026-01-12 10:10:47+00:00       2026-01-12 20:10:41+00:00       2026-01-19 10:10:41+00:00       AES_256_CTS_HMAC_SHA_196        sga-ar-win-dc.attackrange.local
0x2af64e5bcb0   SGA-AR-WIN-WKST$        krbtgt/ATTACKRANGE.LOCAL        AES_256_CTS_HMAC_SHA_196        0x260a10000     2026-01-12 03:31:37+00:00       2026-01-12 13:31:37+00:00       2026-01-14 09:31:31+00:00       AES_256_CTS_HMAC_SHA_196        sga-ar-win-dc.attackrange.local
0x2af64e5be70   SA-MONITORING   ProtectedStorage/sga-ar-win-dc.attackrange.local        AES_256_CTS_HMAC_SHA_196        0x40a50000      2026-01-12 10:10:47+00:00       2026-01-12 20:10:41+00:00       2026-01-19 10:10:41+00:00       AES_256_CTS_HMAC_SHA_196        sga-ar-win-dc.attackrange.local
0x2af64e5c030   SGA-AR-WIN-WKST$        cifs/sga-ar-win-dc.attackrange.local/attackrange.local  AES_256_CTS_HMAC_SHA_196        0x40a50000      2026-01-12 08:18:27+00:00       2026-01-12 16:28:26+00:00       2026-01-14 09:31:31+00:00       AES_256_CTS_HMAC_SHA_196     sga-ar-win-dc.attackrange.local
0x2af64e5c1f0   SGA-AR-WIN-WKST$        cifs/sga-ar-win-dc.attackrange.local    AES_256_CTS_HMAC_SHA_196        0x40a50000      2026-01-12 03:46:37+00:00       2026-01-12 13:31:37+00:00       2026-01-14 09:31:31+00:00       AES_256_CTS_HMAC_SHA_196        sga-ar-win-dc.attackrange.local
0x2af64e5c3b0   SGA-AR-WIN-WKST$        ldap/sga-ar-win-dc.attackrange.local/ATTACKRANGE.LOCAL  AES_256_CTS_HMAC_SHA_196        0x40a50000      2026-01-12 07:48:53+00:00       2026-01-12 16:28:26+00:00       2026-01-14 09:31:31+00:00       AES_256_CTS_HMAC_SHA_196     sga-ar-win-dc.attackrange.local
0x2af64e5c570   SGA-AR-WIN-WKST$        krbtgt/ATTACKRANGE.LOCAL        AES_256_CTS_HMAC_SHA_196        0x140e10000     2026-01-12 06:28:26+00:00       2026-01-12 16:28:26+00:00       2026-01-14 09:31:31+00:00       AES_256_CTS_HMAC_SHA_196        sga-ar-win-dc.attackrange.local
```

These tickets are also dumpable throught the `Dump` command.
