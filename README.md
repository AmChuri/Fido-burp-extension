# Fido-Burp Suite Extension for SDO Analysis
![licence](https://img.shields.io/badge/License-GPLv2-brightgreen.svg)
FIDO-IoT protocol is developed by FIDO Alliance working group and its working implementation has been developed by Intel. This Burp Suite extension is developed to perform evaluation of some basic possible attacks on the library in semi automatic way.

The extension has been developed as part of a master thesis at the [Universität Paderborn](upb.de) in cooperation with the [Devity GmbH](Devity.eu).
## Feautures
- Automatic attack execution [SSRF, Signature Exclusion, Key Confusion]
- Store Certificates/keys in auto exported JSON file.
- Sign custom messages

### Requirements
- Enviornment - [https://gradle.org/][Gradle]
- OS Ubuntu 16.04
- Pre Installed [https://secure-device-onboard.github.io/docs/][SDO Protocol]

#### Build 
```sh 
gradle clean build
```
#### Upload FIDO-IOT JAR file to Burp Suite Extender Tab

Enjoy Testing.