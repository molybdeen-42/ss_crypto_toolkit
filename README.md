# Cryptographic Inventory Toolkit

Een toolkit voor het maken van een cryptografische inventaris met behulp van CycloneDX 1.6 formaat CBOMs (Cryptographic Bills of Material).

## Features

- **Automated TLS scanning**: Het scannen van meerdere doelhosts voor hun SSL/TLS algoritmen
- **CBOM parsing**: Scanoutput van doelhosts wordt automatisch omgezet naar het CycloneDX 1.6 CBOM formaat
- **Validation**: Gegenereerde CBOMs worden gecontroleerd op validiteit

## Quick Start

Start door deze repository te clonen: `git clone https://github.com/molybdeen-42/ss_crypto_toolkit.git`.

### 1. Dependencies

Deze stap installeert de dependencies `testssl.sh` en `cyclonedx-cli`, en zet de rest van de benodigde bestanden op:
- `cd ss_crypto_toolkit`
- `chmod +x setup.sh`
- `./setup.sh`

### 2. Configureer targets.txt

Edit `targets.txt` in de `ss_crypto_toolkit` directory door per line een target van de vorm `ip:port` toe te voegen:

```
192.168.1.42:443
127.0.0.1:22
10.0.0.1:8443
```

### 3. Scannen

De scanscripts maken gebruik van `targets.txt` om de scan uit te voeren op deze targets. De resultaten worden in `ss_crypto_toolkit/results` en `ss_crypto_toolkit/cboms` geplaatst. Een simpele scan kan als volgt worden uitgevoerd:

`./scanning/remote_scan.sh -o exampledirectory1`

Om een nieuwe scan te forceren kan de `-f` flag gebruikt worden:

`./scanning/remote_scan.sh -o exampledirectory2 -f`

De ruwe scanresultaten zijn te vinden in `ss_crypto_toolkit/results`, terwijl de meest recente CBOMs aanwezig zijn in `ss_crypto_toolkit`. 

**LET OP**: De naam van de directory (in het voorbeeld exampledirectory1/2) mag enkel letters en getallen bevatten.
