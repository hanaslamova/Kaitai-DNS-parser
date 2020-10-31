# Kaitai popis aplikačního protokolu - DNS
Předmět: PDS 2019/2020

Autor: Hana Slámová (xslamo00)

Tento parser je založen již na předešlé práci: [https://formats.kaitai.io/dns_packet/index.html]

## Obsah, přehled dokumentace

**Struktura DNS paketu** popisuje formát hlavičky i dat. Obsahuji i formát jednotlivých typů záznamu protokolu DNS.

**Datové typy** obsahují přehled vytvořených datových typů. Některé jsou specifikovány v RFC, některé byly vytvořeny jen za účelem snadnejší implementace typů záznamů nebo vyšší čitelnosti kódu.

Část **nedostatky parseru** popisuje problémy, se kterými jsem se během implementace DNS parseru setkala. Obsahuje i seznamy typů DNS záznamů, které nejsou implementované z důvodu nenalezení jejich specifikace nebo z důvodu, že jsou označeny jako OBSOLETE. 

**Dataset**  byl vytvořen z nalezených PCAP souborů na internetu:
- [https://wiki.wireshark.org/SampleCaptures]
- [https://packetlife.net/captures/protocol/dns/]
- [https://weberblog.net/the-ultimate-pcap/]

Část datasetu byla generována za pomocí vytvořeného privátního DNS serveru (Bind 9), bohužel tento DNS server nepodporoval všechny potřebné typy DNS záznamu a tak i část datasetu byla vytvořena za pomocí hex editoru.

Obsah datasetu je popsán na konci této dokumentace. Každý typ DNS záznamu má svůj PCAP soubor, jehož jméno je jménem záznamu (např. NS - NS.pcap). Každý PCAP soubor pak dále obsahuje query a response DNS zprávu (pozn. některé PCAP soubory query zprávu neobsahují, v pozdější fázi vypracování projektu jsem si uvědomila, že moc velký smysl jejich zachytávání nemá, neboť daný format i data jsou pak i v příslušné DNS response zprávě). Aplikační vsrtva response zprávy je pak i uložena jako binární soubor - *response.bin. 

## Struktura DNS paketu
### Hlavička
Hlavička DNS request/response paketu vypadá následovně [RFC 6895, str. 2]:

     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   OpCode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                QDCOUNT/ZOCOUNT                |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                ANCOUNT/PRCOUNT                |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                NSCOUNT/UPCOUNT                |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

Takováto struktura hlavičky je identická pro všechny typy paketu. Význam polí QDCOUNT/ZOCOUNT, ANCOUNT/PRCOUNT, NSCOUNT/UPCOUNT je u všech typů paketů, kromě paketů pro aktualizaci informací o zónách, stejný:
 - QDCOUNT/ZOCOUNT - počet query záznamů
 - ANCOUNT/PRCOUNT - počet answer záznamů
 - NSCOUNT/UPCOUNT - počet authority záznamů

Význam u paketů sloužících pro dynamickou aktualizaci informací o zónách (OPCODE ve **flags** má hodnotu 5) je následující:
 - QDCOUNT/ZOCOUNT - počet zone záznamů
 - ANCOUNT/PRCOUNT - počet prerequisite  záznamů
 - NSCOUNT/UPCOUNT - počet update záznamů

Dynamický update lze nalézt v souboru dynamicUpdate.pcap.

V parseru lze druhý řádek hlavičky, který obsahuje několik příznaků, nalézt pod názvem **flags**, který je typu ```dns_flags```. Pro ostatní pole hlavičky jsou použity nativní typy.

### Data
Hlavičku mohou následovat data (Resource records), které můžeme rozdělit do sekcí. Každá sekce dat je tvořena záznamy. Počet záznamů v jednotlivých sekcích je určen hodnotami v polích hlavičky - QDCOUNT, ANCOUNT, NSCOUNT atd. Struktura záznamu je pro všechny sekce stejná (některé sekce nevyužívaji všechny zmíněné pole), lze ji vidět níže [RFC 6895, str. 5]:

     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                     NAME                      /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     TYPE                      |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     TTL                       |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                    RDATA                      /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

**NAME** je jméno uzlu (vlastníka), ke kterému se tento záznam váže. Skládá se z několika polí typu ```label``` [RFC 6895, str. 5].

**TYPE** představuje typ záznamu, v parseru jsou reprezentováný následující:

- 1     A
- 2     NS
- 5     CNAME
- 6     SOA
- 7     MB
- 8     MG
- 9     MR
- 10    NULL
- 11    WKS
- 12    PTR
- 13    HINFO
- 14    MINFO
- 15    MX
- 16    TXT
- 17    RP
- 18    AFSDB
- 19    X25
- 20    ISDN
- 21    RT
- 22    NSAP
- 23    NSAP_PTR
- 24    SIG
- 25    KEY
- 26    PX
- 27    GPOS
- 28    AAAA
- 29    LOC
- 31    EID
- 32    NIMLOC
- 33    SRV
- 34    ATMA
- 35    NAPTR
- 36    KX
- 37    CERT
- 39    DNAME
- 40    SINK
- 41    OPT
- 42    APL
- 43    DS
- 44    SSHFP
- 45    IPSECKEY
- 46    RRSIG
- 47    NSEC
- 48    DNSKEY
- 49    DHCID
- 50    NSEC3
- 51    NSEC3PARAM
- 52    TLSA
- 53    SMIMEA
- 55    HIP
- 56    NINFO
- 57    RKEY
- 58    TALINK
- 59    CDS
- 60    CDNSKEY
- 61    OPENPGPKEY
- 62    CSYNC
- 63    ZONEMD
- 99    SPF
- 100   UINFO
- 101   UID
- 102   GID
- 103   UNSPEC
- 104   NID
- 105   L32
- 106   L64
- 107   LP
- 108   EUI48
- 109   EUI64
- 249   TKEY
- 250   TSIG
- 251   IXFR
- 252   AXFR
- 253   MAILB
- 255   ANY
- 256   URI
- 257   CAA
- 258   AVC
- 259   DOA
- 260   AMTRELAY
- 32768 TA
- 65281 WINS
- 65282 WINS_R
- 65422 XPF

Je reprezentován 16 bitovým unsigned integerem [RFC 6895, str. str 5]. Informace o tom, jaké typy záznamů implementovat, byly brány z této stránky [https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml].

Podle **CLASS** pole **NAME** může mít různý význam. Struktura pole **NAME** se ale nemění. Pole **CLASS** má většinou hodnotu IN [RFC 6895, str. 10]. Je reprezentován 16 bitovým unsigned integerem [RFC 6895, str. str 5]

**TTL** specifikuje dobu v sekundách, po kterou může být záznam uložen v cache paměti. Nula zamená, že záznam nesmí byt uložen v cache paměti. Je reprezentován 32 bitovým unsigned integerem [RFC 6895, str. str 6]

**RDLENGHTH** specifikuje délku pole **RDATA**. Je reprezentován 16 bitovým unsigned integerem [RFC 6895, str. str 6]

**RDATA** formát tohoto pole se liší dle hodnoty pole **TYPE**, v některých případech v kombinaci i s hodnotou pole **CLASS** [RFC 6895, str. 6].

Jak bylo zmíněno výše, existuje sekce, která nevyužívá všechna zmíněná pole. Touto sekcí je query. Sekce query vypadá vždy následovně, bez ohledu na hodnotu pole TYPE.

     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                     NAME                      /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     TYPE                      |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

#### A    
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ADDRESS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

Pole **ADDRESS** je délky 32 bitů [RFC 1035, str. 19]. 

#### NS

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   NSDNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

**NSDNAME**  je typu ```domain_name``` [RFC 1035, str. 17].

#### CNAME
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                     CNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

**CNAME** je typu ```domain_name``` [RFC 1035, str. 13].


#### SOA

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                     MNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                     RNAME                     /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    SERIAL                     |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    REFRESH                    |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     RETRY                     |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    EXPIRE                     |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    MINIMUM                    |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    
Následující informace jsou čerpány z [RFC 1035, str. 18] a [RFC 192, str. 3].

**MNAME** je typu ```domain_name```.

**RNAME** je typu ```domain_name```. 

**SERIAL** je 32 bitový unsigned integer.

**REFRESH** je 32 bitový integer.

**RETRY** je 32 bitový integer.

**EXPIRE** 32 bitový integer.

**MINIMUM** 32 bitový integer. Minimální hodnota pole TTL.

#### MB
Informace k tomuto typu DNS záznamu jsou k dispozici v [RFC 1035, str. 13].
Tento typ obsahuje pouze jedno pole **MADNAME**, které má datový typ ```domain_name```. 

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   MADNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

#### MG
Veškeré info lze opět nalézt v [RFC 1035, str. 15].
Tento typ obsahuje pouze jedno pole **MGDNAME**, které má datový typ ```domain_name```. 

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   MGNAME                      /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

#### MR
Informace v [RFC 1035, str. 16].
Obsahuje jen jedno pole **NEWNAME**, které má datový typ ```domain_name```. 

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   NEWNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

#### NULL
V [RFC 1035, str. 17] je tento protokol specifikován jako záznam, který může obsahovat cokoliv, co je velikostí rovno nebo menší 65535 bytům.

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                  <anything>                   /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

Tento typ záznamu lze v parseru nalézt pod jménem ```null_record``` (v jazyce Kaitai null není povoleno používat jako identifikátor). Jelikož tento typ záznamu nemá specifikovánou strukturu RDATA, není tato část parserem více zpracovávaná a tedy pole RDATA neobsahuje další položky, jak je to v případě jiných typů záznamů, ale přímo data délky RDLENGTH.

#### WKS
RDATA pole má následující strukturu [RFC 1035, str. 20]:

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ADDRESS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |       PROTOCOL        |                       |
    +--+--+--+--+--+--+--+--+                       |
    |                                               |
    /                   <BIT MAP>                   /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

**ADDRESS** je 32 bitová internetová adresa. POle je zprcováno jako ADDRESS v záznamu A.
**PROTOCOL** 8 bitové číslo protokolu
**BIT MAP** pole je variabilní délky, které je násobkem osmi. Každý bit představuje port protokolu. Bit 0 je port 1 atd... 

BIT MAP je v parseru reprezentován jako pole bytů délky RDLENGTH-5.

Čísla prokolů a portů lze nalézt v [RFC 1010].

#### PTR
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   PTRDNAME                    /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

**PTRDNAME** je pole typu ```domain_name``` [RFC 1035, str. 17].

#### HINFO
Následující informace jsou čerpány z [RFC 1035, str. 13].

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                      CPU                      /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                       OS                      /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

**CPU** je typu ```character_string``` a říká typ CPU

**OS** je typu ```character_string``` a říká typ operčního systému

Standardní hodnoty polí výše lze nalézt v [RFC 1010].

#### MINFO
Náledující informace jsou čerpány z [RFC 1035, str. 15]

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                    RMAILBX                    /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                    EMAILBX                    /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

Obě pole **RMAILBX**, **EMAILBX** jsou typu ```domain_name```.

#### MX
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                  PREFERENCE                   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   EXCHANGE                    /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

Pole **PREFERENCE** nabývá nějakou hodnotou 16 bitového integeru, která specifikuje prioritu danou tomuto záznamu mezi ostatnímy záznamy od stejného vlastníka. Nižší hodnoty mají větší prioritu [RFC 1035, str. 16]. 

**EXCHANGE** je typu ```domain_name``` a představuje doménové jméno poštovního serveru [RFC 1035, str. 16].

#### TXT

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   TXT-DATA                    /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

Pole **TXT-DATA** obsahuje jeden nebo více hodnot typu ```character_string``` [RFC 1035, str. 17].

#### RP
Definice tohoto typu zprávy je definována ve [RFC 1183,str. 3].

Struktura této zprávy je popsána následovně:

\<owner> \<ttl> \<class> RP \<mbox-dname> \<txt-dname>
kde políčka po RP je jen jiný způsob popisu hlavičky celé odpovědi. Až pole \<mbox-dname>  a \<txt-dname> nesou informace ohledně RP záznamu.

\<mbox-dname>  je typu ```domain_name``` a specifikuje poštovní schránku zodpovědné osoby za doménové jméno.

\<txt-dname> je také typu ```domain_name``` a jedná se o doménové jméno pro které existuje TXT záznam.


#### AFSDB
Informace v [RFC 1183, str. 1].

RDATA sekce má formát \<subtype> \<hostname>, kde subtype je 16 bitový integer a hostname je typu ```domain_name```.

#### X25
RDATA obsahuje pouze jedno pole a to \<PSDN-address> [RFC 1183, str. 5]. Formát tohoto pole je ```character_string```, stejně jako například v TXT.

#### ISDN
Podle [RFC 1183, str. 6] má ISDN RDATA formát následující:  \<ISDN-address> \<sa>. Obě pole jsou typu ```character_string```. Pole \<sa> není povinné.

#### RT
Tento typ je popsán v [RFC 1183, str. 7]. Jeho RDATA část obsahuje dvě položky: \<preference> a \<intermediate-host>. Jedná se o 16 bitový integer a doménové jméno, tedy typ ```domain_name```.

#### NSAP
Obsahuje pole libovolné délky reprezentující hexadecimální posloupnost [RFC 1706, str. 5]. V parseru je toto pole pojmenováno  ```nsap_data ```, zmíněný dokument nedefinuje název, a tak byl převzat z nástroje Wireshark. Kaitai také neumožňuje data reprezentovat hexadecimálně, a tak jsou zobrazena jako pole 8 bitových integerů.

#### NSAP_PTR
Definován v [RFC 1348]. RDATA obsahují pouze jedno pole a to **NSAP-address**. Jedná se o typ ```character_strings```.

#### SIG
V [RFC 2535, str. 17] je RDATA uvedeno následovně:

                           1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |        type covered           |  algorithm    |     labels    |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                         original TTL                          |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                      signature expiration                     |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                      signature inception                      |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |            key  tag           |                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         signer's name         +
      |                                                               /
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-/
      /                                                               /
      /                            signature                          /
      /                                                               /
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


- **type covered** je 16 bitový unsigned integer prezentován typem ```type_type``` 
- **algorithm** je 8 bitový unsigned integer reprezentován enumem ```key_algorithm``` - **labels** je 8 bitový unsigned integer
- **original TTL** 64 bitový unsigned integer
- **signature expiration** a **signature inception** mají být prezentovány jako časová razítka, jelikož jsem ale nepřišla na způsob jak toto uskutečnit v jazyce Kaitai, ponechala jsem je jako 64 bitové unsigned inetegery
- **key tag** je 16 bitový unsigned integer
- **signers name** je reprezentováno jako ```domain_name```
- **signature** má být reprezentováno jako pole hexadecimálních číslic, v parseru je ale repezentováno jako pole 8 bitových inetegerů. 

#### KEY
Formát RDATA vypadá následovně [RFC 2535, str. 9]:

                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |             flags             |    protocol   |   algorithm   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               /
    /                          public key                           /
    /                                                               /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|

- **flags** je 16 bitový integer, v parseru je reprezentován typem ```key_flags```.
- **protocol** je 8 bitový integer a pro jeho snažší interpretaci je využito enum ```key_protocol```
- **algorithm** je též 8 bitový integer, je interpretován enumem ```key_algorithm```. - **public key** je v parseru reprezentováno jako pole 8 bitových integerů.

#### PX
Obsah RDATA je formátován následovně[RFC 1664, str. 6]:

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                  PREFERENCE                   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                    MAP822                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                    MAPX400                    /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

**PREFERENCE** je 16 bitový integer, **MAP822** a **MAPX400** jsou typu ```domain_name```.

#### GPOS
Tneto typ záznamu je specifikován v dokumentu [RFC 1712].

        MSB                                        LSB
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        /                 LONGITUDE                  /
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        /                  LATITUDE                  /
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        /                  ALTITUDE                  /
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

- **LONGITUDE**, **LATITUDE**, **ALTITUDE** jsou zapsána ve formátu čísla s plovoucí řádkou zaodována jako ASCII řetězec, jsou tedy reprezetnována typem ```character_string```.

#### AAAA
Toto rozšíření je popsané v [RFC 1886].

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ADDRESS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

Pole **ADDRESS** je délky 128 bitů [RFC 3596, str. 2]. Je prezentován jako pole bytů délky 16.

#### LOC
Tento typ DNS zprávy je popsán v [RFC 1876].

    MSB                                           LSB
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    0|        VERSION        |         SIZE          |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    2|       HORIZ PRE       |       VERT PRE        |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    4|                   LATITUDE                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    6|                   LATITUDE                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    8|                   LONGITUDE                   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    10|                   LONGITUDE                   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    12|                   ALTITUDE                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    14|                   ALTITUDE                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

Pole **VERSION** musí vždy obsahovat hodnotu nula, jinak pro zbytek dat není definován význam. Pokud tedy hodnota není rovna nule,
zbytek polí je parserem interpretován jako 15 bytové ASCII pole.

Zbylé pole jsou interpretována jako unsigned integer odpovídající délky.

#### EID
Informace v [http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt].
Podle dokumentu obsahuje pouze jedno pole, které obsahuje Endpoint Identifier. V parseru je pojmenován **endpoint_identifier**. Jedná se o pole 8 bitových integerů.

#### NIMLOC
Informace v [http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt].
Podle dokumentu obsahuje pouze jedno pole, které obsahuje Nimrod Locator. V parseru je pojmenován **nimrod_locator**. Jedná se o pole 8 bitových integerů.

#### ATMA
Informace v [https://web.archive.org/web/20190314135249/http://www.broadband-forum.org/ftp/pub/approved-specs/af-dans-0152.000.pdf, str. 14].

RDATA obsahují:
- **FORMAT** - 8 bitový unsigned integer, určující formát pole  ADDRESS
- **ADDRESS** - pole s variabilní délkou, toto pole je v parseru reprezentováno jako pole 8 bitových integerů

#### SRV
Toto rozšíření je popsané v [RFC 2052].

RDATA má následující formát:
- **priority** je 16 bitový unsigned integer
- **weight** je 16 bitový unsigned integer
- **port** je 16 bitový unsigned integer
- **target** je typu ```domain_name```

Tento typ záznamu má trošku odlišnou hlavičku oproti ostatním záznamům. Většina záznamů začíná obsah polem **NAME**, **TTL** atd.. SRV před **NAME** má pole **Service**, **Proto**. Tyto nová pole více specifikují (interpretují) pole **NAME**, nejedná se teda o nová pole ve smyslu, že by byla přidána data. V parseru tato pole nejsou nijak viditelná, jsou součásti pole **NAME**.

#### NAPTR
Tento typ zprávy je popsán v [RFC 3408].

     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     ORDER                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   PREFERENCE                  |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                     FLAGS                     /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   SERVICES                    /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                    REGEXP                     /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                  REPLACEMENT                  /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

Pole **ORDER**, **PREFERENCE** jsou typu unsigned 16 bitovy integer.
Pole **FLAGS**, **SERVICES**, **REGEXP** typu ```character_string```.
Pole **REPLACEMENT** je typu ```domain_name```

#### KX
Formát RDATA je následující [RFC 2230, str. 7]:

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                  PREFERENCE                   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   EXCHANGER                   /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

**PREFERENCE** je pozitivní 16 bitový integer, **EXCHAGER** je typu ```domain_name```.

#### CERT
Formát tohoto typu vypadá takto [RFC 4398, str. 2]:

                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |             type              |             key tag           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   algorithm   |                                               /
    +---------------+            certificate or CRL                 /
    /                                                               /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|

Následující informace jsou převzaty z [RFC 4398, str.5]:
**type** je 16 bitový unsigned integer, pro snažší interpretaci je v parseru využito enum ```cert_type_enum``` [RFC 4398, str. 3]. **key tag** pole je reprezentováno jako unsigned 16 bitový integer. **algorithm** je 8 bitový unsigned integer a **certificate or Crl** pole je reprezentováno v  base64, toto ovšem Kaitai neumožňuje, a tak je tato část záznamu reprezentována jako pole osmi bitových integerů.

Pole **algorithm** má stejný význam hodnot jako v záznamu DNSSKEY, proto je zde využito enumu ```dnssec_algorithm_enum``` [RFC 4398, str. 3].

#### DNAME
Záznam je popsán v [RFC 2672]. Formát RDATA se skládá z pouze jednoho pole - **target**. Toto pole je typu ```domain_name```.

#### SINK
Tento typ záznamu nikdynebyl standardizován, je dotupný pouz jheo draft [https://tools.ietf.org/html/draft-eastlake-kitchen-sink-02#section-2]. V něm je popsáno následující:
RDATA vypdají následovně:

                                          1  1  1  1  1  1
            0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
          +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
          |         coding        |       subcoding       |
          +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
          |                                               /
          /                     data                      /
          /                                               /
          +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

**coding** i **subcoding** jsou 8 bitové unsigned integery. Jejich možné hodnoty jsou reprezentovány datovými typy ```sink_coding_enum```,```sink_subcoding_asn_enum```,```sink_subcoding_mime_enum```,```sink_subcoding_text_enum``` [str. 3-5].

Pole **data** je prezentováno jako base64 [str. 6]. Opět ale v parseru je prezentováno jako pole bytů.

#### OPT
Tento protokol je popsán v [RFC 6891]. 

Má mírně jinou strukturu - místo pole **CLASS** má pole **udp_payload_size** (ve specifikaci není uveden název pole, byl tedy převzat z nástroje Wireshark), místo **TTL** má následující pole [RFC 6891, str. 8]:

                +0 (MSB)                            +1 (LSB)
       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    0: |         EXTENDED-RCODE        |            VERSION            |
       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    2: | DO|                           Z                               |
       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

- **EXTENDED-RCODE** je 8 bitový unsigned integer
- **VERSION** je 8 bitový unsigned integer
- **DO** má délku 1 bit
- **Z** má délku 15 bitů, toto pole nemá význam, je rezervováno pro budoucí rozšíření

Význam změn hlavičky oproti ostatním typům záznamů lze vidět v tabulce nížě [RFC 6891, str. 6]:

        +------------+--------------+------------------------------+
        | Field Name | Field Type   | Description                  |
        +------------+--------------+------------------------------+
        | NAME       | domain name  | MUST be 0 (root domain)      |
        | TYPE       | u_int16_t    | OPT (41)                     |
        | CLASS      | u_int16_t    | requestor's UDP payload size |
        | TTL        | u_int32_t    | extended RCODE and flags     |
        | RDLEN      | u_int16_t    | length of all RDATA          |
        | RDATA      | octet stream | {attribute,value} pairs      |
        +------------+--------------+------------------------------+

Formát pole RDATA je následující [RFC 6891, str. 7]:

                  +0 (MSB)                            +1 (LSB)
       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    0: |                          OPTION-CODE                          |
       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    2: |                         OPTION-LENGTH                         |
       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    4: |                                                               |
       /                          OPTION-DATA                          /
       /                                                               /
       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
- **OPTION-CODE** je 16 bitový unsigned integer, který jednu z hodnot popsaných zde [https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11]. Toto pole je prezentováno v parseru enumem ```opt_option_code_enum```.

- **OPTION-LENGTH** je 16 bitový unsigned integer 
- **OPTION-DATA** je pole 8 bitový integerů, délky **OPTION-LENGTH**, jejich význam je dán dle **OPTION-CODE**

#### APL
Tento typ záznamu je popsán v [RFC 3123].

      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |                          ADDRESSFAMILY                        |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      |             PREFIX            | N |         AFDLENGTH         |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
      /                            AFDPART                            /
      |                                                               |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

APL záznam  obsahuje několik tzv. apl-item, který jsou v parseru reprezentovány typem ```apl_item```. Formát tohoto typu lze vidět výše.

**ADDRESSFAMILY** je 16 bitový usigned integer, **PREFIX** je 8 bitový unsigned integer, **N** má délku 1 bit, **AFDLENGTH** je 7 bitový unsigned integer, **AFDPART** má délku variabilní.  **AFDPART** je prezentován jako data v A případně AAAA záznamu.

Celková délka tohoto itemu je variabilní.

#### DS
Typ DS je popsán v [RFC 4034, str. 15].

                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Key Tag             |  Algorithm    |  Digest Type  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /                                                               /
    /                            Digest                             /
    /                                                               /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Pole **Key Tag**, **Algorithm**  a **Digest type** jsou unsigned integer.
Pole **Digest** obsahuje zbytek prostoru RDATA, které není zabráno výše uvedenýmy poly a měel by být reprezentován jako sekvence hexadecimálních číslic. Bohužel tuto možnost Kaitai nepodporuje, a tak je toto pole reprezentováno jako posloupnost bytů.

#### SSHFP
Informace k tomuto typu DNS záznamu lze nalézt v [RFC 4255].

    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   algorithm   |    fp type    |                               /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               /
    /                                                               /
    /                          fingerprint                          /
    /                                                               /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Pole **algorithm** i **fp type** jsou typu 8 bit integer. Jelikož podle výše zmíněné specifikace jsou zmíněny jejich hodnoty od nuly a výše, v parseru jsou naimplementovány jako unsigned integer.
Pole **fingerprint** má být reprezentováno jako sekvence hexadecimálních číslic, toto v Kaitai není možné, proto byla zvolena reprezentace pomocí pole 8 bitových integerů.

#### IPSECKEY
Je popsán v [RFC 4025]:



       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |  precedence   | gateway type  |  algorithm  |     gateway     |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-------------+                 +
      ~                            gateway                            ~
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               /
      /                          public key                           /
      /                                                               /
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|

- **precedence** je 8 bitový integer
- **gateway type** je 8 bitový unsigned integer prezentovaný enumem ```ipseckey_gateway_type_enum```
- **algorithm** je 8 bitový unsigned integer prezentovaný enumem ```ipseckey_algorithm_enum```
- **gateway** může být jedním ze tří typů - ```domian_name```, adresa IPv4, adresa IPv6 - na základě hodnoty gateway type, toto pole nemusí být v RDATA vždy přítomné
- **public key** má být prezentováno v kódování base64, v parseru je ale prezentováno jako pole 8 bitových integerů, toot pole také neni povinné, zda je v RDATA obsaženo lze zjistit podle hodnoty pole algorithm

Při implementaci aplikace vhodného typu pro pole gateway jsem se setkala s následujícím problémem. Původně jsem tuto situaci chtěla vyřešit následovně:

      - id: gateway_type
        type: u1
      - id: algorithm
        type: u1
      - id: gateway
        type:
          switch-on: gateway_type
          cases:
            1: ipv4
            2: ipv6
            3: domain_name
      - id: public_key
        size: rdlength -3 - gateway.size

Bohužel, tuto konstrukci mi Kaitai nepřijal (called attribute 'length' on generic struct expression 'Name(identifier(gateway))') a tak jsem se rozhodla pro následující řešení:

- místo jednoho pole gateway jsou pole tři: gateway_domain_name, gateway_ipv4, gateway_ipv6
- v jednom okamžiku je však přítomno pouze jedno znich
- Poznámka: mít tři pole jednoho názvu (gateway), která jsou podmíněna, v Kaitai nelze implementovat

#### RRSIG
Informace jsou čerpány z [RFC 4034].

                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |        Type Covered           |  Algorithm    |     Labels    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Original TTL                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Signature Expiration                     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Signature Inception                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |            Key Tag            |                               /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         Signer's Name         /
    /                                                               /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /                                                               /
    /                            Signature                          /
    /                                                               /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

- **Type Covered** je 16 bitový unsigned ineteger, interpretován enumem ```type_type```
- **Algorithm** je 8 bitový unsigned integer, interpretován enumem ```key_algorithm```
- **Labels** je 8 bitový unsiged integer
- **Original TTL** je 32 bitový unsigned integer
- **Signature Expiration** a **Signature Inception** jsou 32 bitový unsigned integery, mají byt reprezentovány jako časová razítka, toto v Kaitai ale neni možnos uskutečnit
- **Key Tag** 16 bitový unsigned integer
- **Signer's Name** je typu ```domain_name```
- **Signature** má být prezentováno jako Base64, v parseru je prezentováno jako pole 8 bitových integerů

#### NSEC
RDATA NSEC jsou ukázána níže [RFC 4034, str. 12]:

                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /                      Next Domain Name                         /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /                       Type Bit Maps                           /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

**Next Domain Name** je typu ```domain_name```. **Type Bits Maps** je skládá z tzv. bit items, který mají strukturu WindowNumber (1 byte), Length (1 byte), pole bytů, kde jednotlivý bit značí zda daný DNS record type existuje na vlastníkovi NSEC záznamu. Pro přesnější vysvetlení [RFC 4034, str. 12]. Pole Type Bits Map je prezentováno strukturou ```bitmaps```.

#### DNSKEY
Struktura obsahu DNSKEY zaznamu je popsána v [RFC 4034, str.3].

                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |              Flags            |    Protocol   |   Algorithm   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /                                                               /
    /                            Public Key                         /
    /                                                               /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

**Pole Flags**, **Protocol**, **Algorithm** jsou unsigned integery, délky podle obrázku výše. Public Key má být podle standardu reprezentováno v Base64, toto bohužel Kaitai neumožňuje a tak je toto pole reprezentováno jako pole 8 bitových integerů.

#### DHCID
V [RFC 4701, str. 3] je popsán formát následovně:


    < 2 octets >    Identifier type code
    < 1 octet >     Digest type code
    < n octets >    Digest (length depends on digest type)

dále na stejné stránce je popásna prezentace dat - RDATA jsou prezentována jako jeden blok dat, ketrý je zobrazen jako BASE64. V parseru jsou RDATA teda zobrazena jako pole bytů pod názvem dhcid_data.

#### NSEC3
Informace v [RFC 5155, str. 8]:

                            1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   Hash Alg.   |     Flags     |          Iterations           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Salt Length  |                     Salt                      /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Hash Length  |             Next Hashed Owner Name            /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /                         Type Bit Maps                         /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

**Hash Alg.** je 8 bitový unsigned integer, **Flags** je také unsigned 8 bitový integer, který má mít hodnotu 0, **Iterations** je 16 bitový unsigned integer, **Salt Length** je 8 bitový unsigned integer, **Salt** má být reprezentováno jako binární oktety, v parseru je prezentováno jako pole 8 bitových integerů. **Hash Length** je 8 bitový unsigned integer, **Next hashed Owner Name** je délky **Hash Length** a má být  v binárním formátě. V parseru je interpretváno jako pole 8 bitových integerů. **Type Bit Maps** je totožné s Type Bit Maps v záznamu NSEC.

#### NSEC3PARAM
Informace v [RFC 5155, str. 11]:

                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   Hash Alg.   |     Flags     |          Iterations           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Salt Length  |                     Salt                      /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

**Hash Alg.** je 8 bitový unsigned integer, **Flags** je také unsigned 8 bitový integer, který má mít hodnotu 0, **Iterations** je 16 bitový unsigned integer, **Salt Length** je 8 bitový unsigned integer, **Salt** má být reprezentováno jako binární oktety, v parseru je prezentováno jako pole 8 bitových integerů.

#### TLSA
Tento protokol je popsán v [RFC 6698].

                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Cert. Usage  |   Selector    | Matching Type |               /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               /
    /                                                               /
    /                 Certificate Association Data                  /
    /                                                               /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Pole **Certificate Usage**, **Selector**, **Matching type** jsou typu unsigned 8 bit integer.
**Certificate Association Data** je pak posloupnost hexadecimalnich znaků, ale opět v parseru jsou zobrazeny jako pole bytů.

#### SMIMEA
Dle [RFC 8162, str. 3] RDATA fromát je identický s TLSA.

#### HIP
Informace ohledně tohoto záznamu lze nalézt v [RFC 5205].

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  HIT length   | PK algorithm  |          PK length            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    ~                           HIT                                 ~
    |                                                               |
    +                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                     |                                         |
    +-+-+-+-+-+-+-+-+-+-+-+                                         +
    |                           Public Key                          |
    ~                                                               ~
    |                                                               |
    +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                               |                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
    |                                                               |
    ~                       Rendezvous Servers                      ~
    |                                                               |
    +             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |             |
    +-+-+-+-+-+-+-+

- **HIT length** je 8 bitový unsigned integer, určuje délku pole HIT
- **PK algorithm** je 8 bitový unsigned integer, význam hodnot je stejný jako v záznamu IPSECKEY u pole **algorithm type**, je zde tedy využito enumu ```ipseckey_algorithm_enum```.
-** PK length** je 16 bitový unsigned integer, určuje délku pole **Public Key** 
- **HIT** má být zobrazeno jako pole binárních hodnot, v parseru je zobrazeno jako pole 8 bitových integerů
- **Public Key** má být zobrazeno jako pole binárních hodnot, v parseru je zobrazeno jako pole 8 bitových integerů
- **Rendezvous Servers** obsahuje jedno nebo více ```domain_name```, je tedy využit typ ```domain_names```

#### NINFO
Pro tento typ záznamu byl vytvořen draft ale expiroval před tím, něž se jej podařilo adoptovat [https://en.wikipedia.org/wiki/List_of_DNS_record_types]. Informace, které se mi podařio k tomuto typu nalézt, jsou popsáne zde [https://www.iana.org/assignments/dns-parameters/NINFO/ninfo-completed-template].

Tento typ má mít strukturu RDATA totožnou se záznamem TXT, tedy má jediné pole, které jsem se rozhodla pojmenovat podobně jako právě v TXT - ninfodata.

#### RKEY
Stejný případ jako u NINFO. Níže uvedené informace jsou převzaty z [https://www.iana.org/assignments/dns-parameters/RKEY/rkey-completed-template]. RDATA jsou téměř identická typu KEY, jediný rozdíl jsou hodnoty polí flags a protocol. pole flags je vždy nula a pole protocol je jedna.

                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |             flags             |    protocol   |   algorithm   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               /
    /                          public key                           /
    /                                                               /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|


#### TALINK
Tento typ nemá samostatné RFC, je pouze popsán v draftu [https://www.iana.org/assignments/dns-parameters/TALINK/talink-completed-template]. Ve zmíněném dokumentu je tento záznam popsán jako dvě pole typu ```domain_name```. Jejich názvy nejsou popsány, tak jsem je nazvaa domain_name1 a domain_name2.

#### CDS
Podle [RFC 7344, str. 7] je formát tohoto typu záznamu totožný s formátem typu záznamu DS.

#### CDNSKEY
Podle [RFC 7344, str. 7] je formát tohoto typu záznamu totožný s formátem typu záznamu DNSKEY.

#### OPENPGPKEY
V [RFC 7929, str. 6] se píše, že tento typ záznamu obsahuje pouze jedno pole a to daný klíč. V dokumentu nespecifikují jeho název, proto jsem jej pojmenovala podobně jako ve Wiresharku - **openpgp_key**. Toto pole má být prezentováno jako base6, jelikož toto Kaitai ale neumožňuje, je zorazeno jako pole 8 bitových bytů.

#### CSYNC
CSYNC je popsán v [RFC 7477].

                          1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                          SOA Serial                           |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |       Flags                   |            Type Bit Map       /
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     /                     Type Bit Map (continued)                  /
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

- **SOA serial** je 32 bitový integer
- **Flags** je 16 bitový integer, prezentován typem ```csync_flags```
- **Type Bit Map** pole je zpracováváno stejným způsobem, jako stejnojmenné pole v NSEC

#### ZONEMD
Tento typ záznam nebyl standardizován, tedy neexistuje k němu RFC. Je popsán v tomto dokumentu [https://www.ietf.org/archive/id/draft-wessels-dns-zone-digest-06.txt].

                            1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             Serial                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Digest Type  |   Reserved    |                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
    |                             Digest                            |
    /                                                               /
    /                                                               /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

- **Serial** je 32 bitový unsigned integer
- **Digest Type** je 8 bitový unsigned intege
- **Reserved** je 8 bitový unsigned integer
- **Digest** je pole 8 bitový integerů, podle dokumentu má být ale prezentováno jako pole hexadecimálníh číslic

#### SPF
Struktura dat SPF typu je identická jako TXT [RFC 4408, str.9]. Tedy obsahuje jeden nebo více hodnot typu ```character_string```.
Jelikož ve zmíněném RFC není uveden název pole obsahující sekvenci hodnot typu ```character_string``` a jediné co je uvedeno, že se jedná o stejný
formát jako u typu záznamu TXT, pojmenovala jsem jej obdobně jako u TXT záznamu, tedy spfdata.

#### NID
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Preference           |                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
    |                             NodeID                            |
    +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Výše popsaný formát lze nalézt v [RFC 6742, str. 5]. POle jsou popsána následovně:
- **Preference** - 16 bitový unsigned integer
- **NodeID** - 64 bitů unsigned integer, který má být prezentován jako skupiny 4 hexadecimálních číslic oddělených dvojtečkou. Toto v jazyce Kaitai nelze realizovat a tak jsou data reprezentována jako 64 bitový unsigned ineteger.

#### L32
RDATA vypadají následovně [RFC 6742, str. 6]:

 - **Preference** je 16 bitový unsigned integer
 - **Locator32** je 32 bitový unsigned integer prezentovaný stejným způsobem jako pole **ADDRESS** v A záznamu

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |          Preference           |      Locator32 (16 MSBs)      |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |     Locator32 (16 LSBs)       |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#### L64
RDATA vypadají následovně [RFC 6742, str. 10]:

 - **Preference** je 16 bitový unsigned integer
 - **Locator64** je 64 bitový unsigned integer prezentovaný stejným způsobem jako pole ADDRESS v AAAA záznamu

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |          Preference           |                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
        |                          Locator64                            |
        +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#### LP
RDATA vypadají následovně [RFC 6742, str. 12]:

   - **Preference** je 16 bitový unsigned integer
   - **FQDN** má variabilní délku a prezentováno jako ```domain_name```

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Preference           |                               /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               /
    /                                                               /
    /                              FQDN                             /
    /                                                               /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#### EUI48
RDATA vypadají následovně [RFC 7043, str. 3]:


      0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                          EUI-48 Address                       |
      |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

**EUI-48 Address** je v praseru zobrazeno jako eui48_address. Má být reprezentováno jako dvojice hexadecimálních číslic, odedělené pomlčkou, například takto  00-00-5e-00-53-2a. Toto zobrazení ale není v Kaitai možné, a tak jsou data zobrazena jako pole bytů.

#### EUI64
RDATA vypadají následovně [RFC 7043, str. 3]:

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                          EUI-64 Address                       |
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

**EUI-64 Address** je v praseru zobrazeno jako eui64_address. Má být reprezentováno jako dvojice hexadecimálních číslic, odedělené pomlčkou, například takto  00-00-5e-ef-10-00-00-2a. Toto zobrazení ale není v Kaitai možné, a tak jsou data zobrazena jako pole bytů.

#### TKEY
Tento typ záznamu je popsán v [RFC 2930] následovně (název pole, prezentace v parseru):
       
- **Algorithm**:  ```domain_name```
- **Inception**:   u_int32_t, má být prezentován jako datum a čas, toto ale Kaitai neumožňuje
- **Expiration**:  u_int32_t, ma být taky zobrazeno jako datum a čas
- **Mode**:        u_int16_t, enum ```tkey_mode_enum```
- **Error**:       u_int16_t, enum ```tkey_error_enum```
- **Key Size**:    u_int16_t
- **Key Data**:    pole 8 bitových integerů
- **Other Size**:  u_int16_t
- **Other Data**:  pole 8 bitových integerů


#### TSIG
Následující informace jsou čerpány z [RFC 2845], kde je tento typ zprávy popsán. Jeho RDATA pole obsahuje následující položky:

| název pole         | datový typ    |
| -------------------|:-------------:|
| Algorithm Name     | domain-name   |
| Time Signed        | u_int48_t     |
| Fudge              | u_int16_t     |
| MAC Size           | u_int16_t     |
| MAC                | octet stream  |
| Original ID        | u_int16_t     |
| Error              | u_int16_t     |
| Other Len          | u_int16_t     |
| Other Data         | octet stream  |

domain-name odpovídá Kaitai typu ```domain_name```. veškere zdé uvedené integery jsou implementovány pomocí Kaitai klasických datových typů, kromě u_int48_t. Pro tento datový typ Kaitai nemá podporu. V parseru je tedy položka tohoto typu reprezentována pomocí bytového pole o velikosti 6.

#### IXFR
Podle [RFC 1995] se jedná o typ žádosti. 

#### AXFR
Podle [RFC 1035, str. 12] se jedná o typ žádosti. Žádost o transfer celé zóny.

#### MAILB
Definován v [RFC 1035, str. 12], sám o sobě nepředstavuje typ záznamu ale jedná se pouze o query type - slouží k vyžádání si informací ohledně pošty, tedy pokud query je typu MAILB, klient se ptá na záznamy typu MB, MG nebo MR.

#### ANY
Tento typ záznamu je definován v [RFC 1035, str. 12]. Je zde zmíněno, že pokud je poslán dotaz na tento typ záznamu, klient se dotazuje na všechny typy záznamu, které DNS server má k dispozici.

#### URI
Následující informac ejsou převzaty z [RFC 7553, str. 5]:

                            1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Priority             |          Weight               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /                                                               /
    /                             Target                            /
    /                                                               /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

**Priority** a **Weight** jsou 16 bitový unsigned integery, pole **Target** obsahuje zbytek sekce RDATA a má být prezentováno jako pole 8 bitových bytů.

#### CAA
Tento typ je popsán v [RFC 6844].

    +0-1-2-3-4-5-6-7-|0-1-2-3-4-5-6-7-|
    | Flags          | Tag Length = n |
    +----------------+----------------+...+---------------+
    | Tag char 0     | Tag char 1     |...| Tag char n-1  |
    +----------------+----------------+...+---------------+
    +----------------+----------------+.....+----------------+
    | Value byte 0   | Value byte 1   |.....| Value byte m-1 |
    +----------------+----------------+.....+----------------+

Pole **Flags** je typu 8 bit integer.
**Tag Length** je typu 8 bit unsigned integer.
**Tag** je sekvence ASCII znaků, které mají délky dle hodnoty Tag Length.
**Value** je sekvence 8 bitovych hodnot. Délka tohoto pole je zbytek RDATA pole.

#### AVC
Podle dokumentu [https://www.iana.org/assignments/dns-parameters/AVC/avc-completed-template], ve kterém je tento typ záznamu popsán, má formát RDATA totožný s typem TXT.

#### DOA
Draft tohoto typu záznamu [https://www.ietf.org/archive/id/draft-durand-doa-over-dns-03.txt]. 

       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    0: |                                                               |
       |                        DOA-ENTERPRISE                         |
       |                                                               |
       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    4: |                                                               |
       |                           DOA-TYPE                            |
       |                                                               |
       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    8: |         DOA-LOCATION          |         DOA-MEDIA-TYPE        /
       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
   10: /                                                               /
       /                  DOA-MEDIA-TYPE (continued)                   /
       /                                                               /
       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
       /                                                               /
       /                           DOA-DATA                            /
       /                                                               /
       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

- **DOA-ENTERPRISE** je 32 bitový unsigned integer
- **DOA-TYPE** je 32 bitový unsigned integer
- **DOA-LOCATION** je 8 bitový unsigned integer
- **DOA-MEDIA-TYPE** je ```character_string```
- **DOA-DATA** mají být prezentována jako base64, v parseru jsou ale interpretována jo pole 8 bitových integerů

#### AMTRELAY
Informace lze nalézt zde [https://datatracker.ietf.org/doc/draft-ietf-mboned-driad-amt-discovery/?include_text=1]. 

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   precedence  |D|    type     |                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
    ~                            relay                              ~
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

- **precedence** je 8 bitový integer, stejný význam jako v [RFC 1035, sekce 3.3.9].
- **D** (Discovery Optional) je 1 bit
- **type** 7 bitový unsigned integer, určuje typ dat v poli relay, je zde využito ```ipseckey_gateway_type_enum```
- **relay** je identické poli gateway v typu záznamu IPSECKEY, tedy může být různého typu - ```domain_name```, IPv4, IPv6, tento problém je obdobně řešen právě jako v typu záznamu IPSECKEY 

#### TA
Informace k tomuto typu záznamu lze nalézt v tomto dokumentu [http://www.watson.org/~weiler/INI1999-19.pdf, str. 20]. V dokumentu lze nalézt, že formát tohoto typu záznamu je totožný s typem záznamu DS [http://www.watson.org/~weiler/INI1999-19.pdf, str. 10].

## Datové typy


### domain_name 

Doménové jméno může být reprezentováno následujícímy způsoby [RFC 1035, str. 29]:
- sekvence struktur typu ```label``` zakončena oktetem s hodnotou nula
- strukturou ```pointer```
- sekvence struktur typu ```label``` zakončena strukturou ```pointer```

### label
Label obsahuje 8 bitové pole představující jeho délku. První dva nejvyší  jsou nastaveny na nulu, pokud na jedničku, jedná se o strukturu ```pointer``` [RFC 1035, str. 10].

### pointer
Pole OFFSET specifikuje posunutí od počátku DNS vrstvy paketu [RFC 1035, str. 29].

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    | 1  1|                OFFSET                   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

### character_string 
Character_string je složen z 8 bitového čísla a počtem bajtů daným tímto číslem.
Může být dlouhý až 256 bytů (včetně bytu udávající délku) [RFC 1035, str 12].

### character_strings
Obsauje několik  ```character_string```.

### key_flags
Struktura vytvořena speciálne pro typ záznamu KEY. Jendá se o implementaci pole flags [RFC 2535, str. 10].

### bitmaps
Jedná se o implementaci struktury popsanou například v [RFC 3485, str. 2]. Obsahuje několik polí typu ```bitmap```.

### bitmap
Má strukturu:
- *window_number* je unsigned 8 bitový integer, může nabývat hodnot 0-255
- *bitmap_length* je unsigned 8 bitový integer, určující délku celého *bitmap_items*, může nabývat hodnot 1-32
- *bitmap_items* je pole prvků typu ```bitmap_item```

### bitmap_item
Má strukturu:
- *item* který je jedním z následujících typů: ```bitmap_item_0```, ```bitmap_item_1```, ```bitmap_item_2```,```bitmap_item_3```, ```bitmap_item_4```, ```bitmap_item_5```, ```bitmap_item_6```,```bitmap_item_7```, ```bitmap_item_11```, ```bitmap_item_12```, ```bitmap_item_31```, ```bitmap_item_32```, ```bitmap_item_4096```. Všechny uvedné typy jsou velikosti 8 bitový unsigned integer.
            
Jak je uvedeno v [RFC 3485, str. 2], *item* v ```bitmap_item``` je vždy velikosti 1 byte. Každý *item* kóduje typy záznamů určitý rozsah typů záznamů. Pokud je *window_number*  rovno 0 a index referencovaného prvku v *bitmap_items* je také roven 0, daný byte kóduje na jednotlivých bitech hodnoty od 1 do 7, což odpovídá záznamům A, NS, MD atd.. Nultý bit se ignoruje, neboť žádný typ záznamu nemá přidělenou hodnotu právě 0. Pokud *window_number* je rovno 0 a index referencovaného prvku v *bitmap_items* je roven 1, bity tohoto bytu budou kódovat záznamy s přiděleným číslem 8 až 15 atd...

Pro *window_number* rovnající se 1, první bit prvního prvku v  *bitmap_items* bude korespondovat typu záznamu s hodnotou 257, druhý bit 258 atd...

Určení typu *item* je podle hodnoty pole *window_number* a *index*, což představuje index pole *bitmap_items*. Hodnota *index*+*window_number* *32 určuje daný typ - pokud je hodnota 0 pak ```bitmap_item_0``` je použit, pokud 4096 tak ```bitmap_item_4096``` atd.. Vzoreček vycházi ze znalosti, že *window_number* může mít až 32 prvků v poli *bitmap_items* a představuje tedy něco jako "offset".

Jednotlivé typy ```bitmap_item_*``` pak tedy kódují určité rozsahy hodnot typů áznamů, ```bitmap_item_0``` kóduje prvníh 8 hodnot (A, NS, MD..), ```bitmap_item_1``` kóduje druhou osmici (MG, MR, NULL...) atd...

## Nedostatky parseru

- prezentace dat jako hexadecimální číslice nebo v Base64 kódování - toto jazyk Kaitai neumožňuje, a tak jsou data zobrazena jako pole 8 bitových integerů. Tento rozpor mezi standardem a implementací je uveden u každého typu záznamu, kterého se to týká.

- typ ```domain_name```  a vlastnost length - typ ```domain_name``` obsahuje jedno pole name, které je složeno z několika typů ```label```. Tento počet je variabilní. Během používání typu ```domain_name``` bylo potřeba mít informaci o délce pole tohoto typu. Implementované řešení má ale omezení. Funguje pouze na doménová jména, která neamjí vyšíí počet domén nežli 5.

- Neimplementované typy DNS záznamu - OBSOLETE:
    - 3     MD Podle RFC 1035 se jedná o OBSOLETE záznam.
    - 4     MF Podle RFC 1035 se jedná o OBSOLETE záznam.
    - 30    NXT Definován v RFC 2535 , podle RFC 3755 se jedná o OBSOLETE záznam.
    - 38    A6 Definován v RFC 2874, podle RFC 6563 se jedná o OBSOLETE záznam.
    - 254   MAILA Podle RFC 1035 se jedná o OBSOLETE záznam.
    - 32769 DLV Definován v RFC 4431 , podle 
https://datatracker.ietf.org/doc/draft-ietf-dnsop-obsolete-dlv/ se bude jednat o OBSOLETE záznam.

- neimplementované typy DNS záznamu - nenalezena specifikace:
    - 100   UINFO
    - 101   UID
    - 102   GID
    - 103   UNSPEC
    - 65281 WINS
    - 65282 WINS_R
    - 65422 XPF

## Dataset
První sloupec uvádí název PCAP souboru, druhý sloupec název binárního souboru, obsahující extrahovaná aplikační data paketů z PCAP souboru, třetí obsahuje popis dat v daném binárním souboru.

| PCAP               | bin                            |  obsahuje             |
| -------------      | :---------------:              |:---------------:      |
| A                  | Aresponse.bin                  | 1 A answers           |
| GPOS               | GPOSresponse.bin               | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
|                    |                                | 1 OPT additionals     |
| AAAA               | AAAAresponse.bin               | 1 AAAA answers        |
| LOC                | LOCresponse.bin                | 1 LOC answer          |
|                    |                                | 1 OPT addtitional     |
| EID                | EIDresponse.bin                | 1 EID answer          |
| NIMLOC             | NIMLOCresponse.bin             | 1 NIMLOC answer       |
| ATMA               | ATMAresponse.bin               | 1 ATMA answer         |
| WKS                | WKSresponse.bin                | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
| PTR                | PTRresponse.bin                | 1 PTR answer          |
| MX                 | MXresponse.bin                 | 6 MX answer           |
|                    |                                | 6 A additionals       |
| TXT                | TXTresponse.bin                | 1 TXT answer          |
| RP                 | RPresponse.bin                 | 1 RP answer           |
|                    |                                | 1 OPT addtitional     |
| AFSDB              | AFSDBresponse.bin              | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
|                    |                                | 1 OPT additionals     |
| X25                | X25response.bin                | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
|                    |                                | 1 OPT additionals     |
| ISDN               | ISDNresponse.bin               | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
|                    |                                | 1 OPT additionals     |
| RT                 | RTresponse.bin                 | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
|                    |                                | 1 OPT additionals     |
| NSAP               | NSAPresponse.bin               | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
|                    |                                | 1 OPT additionals     |
| NSAP_PTR           | NSAP_PTRresponse.bin           |                       |
| SIG                | SIGresponse.bin                | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
|                    |                                | 1 OPT additionals     |
| KEY                | KEYresponse.bin                | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
|                    |                                | 1 OPT additionals     |
| PX                 | PXresponse.bin                 | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
|                    |                                | 1 OPT additionals     |
| NS                 | NSresponse.bin                 | 4 NS answer           |
| SOA                | SOAresponse.bin                |                       |
| MB                 | MBresponse.bin                 | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
| MG                 | MGresponse.bin                 | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
| MR                 | MRresponse.bin                 | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
|                    |                                | 1 OPT additionals     |
| NULL               | NULLresponse.bin               | 1 NULL answer         |
| CNAME              | CNAMEresponse.bin              | 4 CNAME answers       |
|                    |                                | 2 A answers           |
|                    |                                | 8 NS authoritative    |
|                    |                                | 7 A additional        |
| SRV                | SRVresponse.bin                | 2 SRV answer          |
| NAPTR              | NAPTRresponse.bin              | 1 NAPTR answer        |
| KX                 | KXresponse.bin                 | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
|                    |                                | 1 OPT additionals     |
| CERT               | CERTresponse.bin               | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
|                    |                                | 1 OPT additionals     |
| DNAME              | DNAMEresponse.bin              |                       |
| SINK               | SINKresponse.bin               | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
|                    |                                | 1 OPT additionals     |
| HINFO              | HINFOresponse.bin              | 1 HINFO answer        |
|                    |                                | 1 OPT addtitional     |
| MINFO              | MINFOresponse.bin              | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
|                    |                                | 1 OPT additionals     |
| APL                | APLresponse.bin                | 1 OPT additionals     |
| DS                 | DSresponse.bin                 | 1 DS answer           |
|                    |                                | 1 OPT addtitional     |
| SSHFP              | SSHFPresponse.bin              | 8 SSHFP answer        |
|                    |                                | 1 OPT addtitional     |
| IPSECKEY           | IPSECKEYresponse.bin           | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
|                    |                                | 1 OPT additionals     |
| RRSIG              | NSEC3,RRSIGresponse.bin        | 1 OPT addtitional     |
|                    |                                | 1 SOA authoritative   |
|                    |                                | 2 NSEC3 authoritative |
|                    |                                | 3 RRSIG authoritative |
| NSEC               | NSECresponse.bin               | 2 DNSKEY answer       |
|                    |                                | 1 OPT addtitional     |
| DNSKEY             | DNSKEYresponse.bin             | 2 DNSKEY answer       |
|                    |                                | 1 OPT addtitional     |
| DHCID              | DHCIDresponse.bin              | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
|                    |                                | 1 OPT additionals     |
| NSEC3              | NSEC3,RRSIGresponse.bin        | 1 OPT addtitional     |
|                    |                                | 1 SOA authoritative   |
|                    |                                | 2 NSEC3 authoritative |
|                    |                                | 3 RRSIG authoritative |
| NSEC3PARAM         | NSEC3PARAMresponse.bin         | 1 NSEC3PARAM answer   |
|                    |                                | 1 OPT addtitional     |
| TLSA               | TLSAresponse.bin               | 1 TLSA answer         |
|                    |                                | 1 OPT addtitional     |
| SMIMEA             | SMIMEAresponse.bin             | 1 SMIMEA answer       |
| HIP                | HIPresponse.bin                | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
|                    |                                | 1 OPT additionals     |
| NINFO              | NINFOresponse.bin              | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
|                    |                                | 1 OPT additionals     |
| RKEY               | RKEYresponse.bin               | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
|                    |                                | 1 OPT additionals     |
| TALINK             | TALINKresponse.bin             | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
|                    |                                | 1 OPT additionals     |
| CDS                | CDSresponse.bin                | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
|                    |                                | 1 OPT additionals     |
| CDNSKEY            | CDNSKEYresponse.bin            | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
|                    |                                | 1 OPT additionals     |
| OPENPGPKEY         | OPENPGPKEYresponse.bin         | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
|                    |                                | 1 OPT additionals     |
| CSYNC              | CSYNCresponse.bin              | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
|                    |                                | 1 OPT additionals     |
| ZONEMD             | ZONEMDresponse.bin             | 1 ZONEMD answer       |
| SPF                | SPFresponse.bin                | 1 SPF answer          |
|                    |                                | 1 OPT addtitional     |
| NID                | NIDresponse.bin                | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
|                    |                                | 1 OPT additionals     |
| L32                | L32response.bin                | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
|                    |                                | 1 OPT additionals     |
| L64                | L64response.bin                | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
|                    |                                | 1 OPT additionals     |
| LP                 | LPresponse.bin                 | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
|                    |                                | 1 OPT additionals     |
| TKEY               | TKEYresponse.bin               |                       |
| IXFR               | IXFRresponse.bin               | 4 SOA answer          |
|                    |                                | 6 RRSIG answer        |
|                    |                                | 3 NSEC answer         |
|                    |                                | 1 A answer            |
| AXFR               | AXFRresponse.bin               | many                  |
|                    |                                | 1 A answer            |
| EUI48              | EUI48response.bin              | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
|                    |                                | 1 OPT additionals     |
| EUI64              | EUI64response.bin              | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
|                    |                                | 1 OPT additionals     |
| ANY                | ANYresponse.bin                | 1 AAAA answer         |
|                    |                                | 1 A answer            |
|                    |                                | 4 NS answer           |
|                    |                                | 1 OPT addtitional     |
| URI                | URIresponse.bin                | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
|                    |                                | 1 OPT additionals     |
| CAA                | CAAresponse.bin                | 3 CAA answer          |
|                    |                                | 1 OPT addtitional     |
| AVC                | AVCresponse.bin                | 1 AVC answer          |
| DOA                | DOAresponse.bin                | 1 DOA answer          |
| AMTRELAYdomainName | AMTRELAYresponseDomainName.bin |                       |
| AMTRELAYipv4       | AMTRELAYresponseIpv4.bin       |                       |
| AMTRELAYipv6       | AMTRELAYresponseIpv6.bin       |                       |
| TA                 | TAresponse.bin                 | 2 NS authoritatives   |
|                    |                                | 2 A additionals       |
|                    |                                | 1 OPT additionals     |
| dynamicUpdate      | dynamicUpdateQuery.bin         |                       |
|                    | dynamicUpdateResponse.bin      |                       |