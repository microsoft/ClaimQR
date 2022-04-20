**NOTE**: this project is a work in progress.

# Claim QR Codes

It is useful for users to be able to present attribute information, or _claims_ about themselves to various relying parties. This commonly happens in online exchanges, through federated protocols such as SAML and OpenID Connect. The situation is quite different in the real-world, where the claims are typically encoded in physical documents (e.g., driver's licenses, employment badges, etc.) in which various measures are employed to protect the integrity of the documents and to attest to their origin.

The advent of COVID vaccination credentials popularized the idea of carrying cryptographically protected claims while presenting them in an offline manner, typically using a QR code. One such popular effort is the [SMART Health Cards](https://smarthealth.cards/) (SHC) framework that enabled millions of people to hold their proofs of vaccination on an electronic device or a paper printout and present them to various verifiers.

This paradigm of showing cryptographically protected claims using a QR code is an interesting one. The ubiquity of smartphones allowing users to hold their claims in a client wallet, and verifiers to easily scan the QR codes for validation, makes it very easy to interact in a user-centric, _ad hoc_ manner.

The goal of this project is to prototype how generic claims (attributes) can be issued to users in the form of a QR code that can be presented to verifiers, who can dynamically discover the issuer and validate the claims. We call this credential a Claim QR (CQR). In this initial release, we are reusing most of the technical specification of the SHC framework to facilitate reusing existing implementations; alternative options and new features will be explored in [future versions](#extensions).

One drawback of long-lived credentials is that all the encoded claims must be disclosed as a whole during presentation, which can lead to over disclosure. This project builds in a selective disclosure mechanism allowing the CQR to be modified by the holder at presentation time to only disclose a subset of the encoded claims.

## System overview

**Claims** (a.k.a. attributes) are issued by an **issuer** to a **holder** (a.k.a. user) in the form of a QR code, which is later presented to a **verifier**. The holder can modify the QR code before presenting it to selectively disclose a subset of the encoded claims (while retaining the integrity of the claim values).

Each issuer participating in the system, identified by a URL `[ISSUER_URL]`, creates a signing key pair, and makes its public key available in a JSON Web Key (JWK) set hosted at `[ISSUER_URL]/.well-known/jwks.json`.

The claims are encoded into a [JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519) (JWT), which is in turn compressed, signed with the issuer private key, and encoded into a QR image.

Verifiers can extract the JWT from presented QR codes after validating the issuer signature: the issuer identifier is first extracted from the QR code, the corresponding public key is either retrieved from its online location or from a local cache. Deciding which issuers to trust is application-specific; some applications could have a pre-determined set of issuers, or a PKI hierarchical approach could be used instead.

In addition to regular, always-disclosed claims, a selectively-disclosable set of claims can be encoded into a `claimDigests` object containing the claim names and corresponding hash digests calculated from random salts and the claim values; the salts and claim values are appended to the QR payload, and can be modified by the holder at presentation to hide a subset of the claims.

The following diagram illustrates the system.

![architecture diagram](img/CQR_architecture.png)

## Claim QR specification

This section contains the specification for Claim QRs.

### Issuer setup

This section specifies the steps to setup a CQR issuer. An issuer is specified by a HTTPS URL `[ISSUER_URL]` without a tailing '/' character.

#### Issuer key generation

An issuer must first create a JSON Web Key (JWK) (see [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)) signing key pair, which SHALL be a Elliptic Curve key using the NIST P-256 curve (identified as algorithm `ES256` in JWS). The private key must be protected using conventional techniques (see, e.g., the JWS [security considerations](https://datatracker.ietf.org/doc/html/rfc7515#section-10)). The public JWK has the following requirements:

* SHALL have the properties "kty": "EC", "use": "sig", and "alg": "ES256"
* SHALL have "kid" equal to the base64url-encoded SHA-256 JWK Thumbprint of the key (see [RFC 7638](https://datatracker.ietf.org/doc/html/rfc7638))
* SHALL have "crv": "P-256, and "x", "y" equal to the base64url-encoded values for the public Elliptic Curve point coordinates (see RFC7518)
* SHALL NOT have the Elliptic Curve private key parameter "d"

#### Issuer key publication

Issuers SHALL publish their public keys in a JWK set (see [section 5 of RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517#section-5)) available at `[ISSUER_URL]/.well-known/jwks.json`, with [Cross-Origin Resource Sharing](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin) (CORS) enabled, using TLS version 1.2 following the IETF [BCP 195](https://www.rfc-editor.org/info/bcp195) recommendations or TLS version 1.3 (with any configuration).

#### Issuer key rotation

Guidelines for key rotation are application-specific; a period of one year is RECOMMENDED by default. A new key pair is generated, and its public key is added to the published JWK set.  

Old private keys SHALL be destroyed; old public keys SHALL remain in the published JWK set until no more valid (unexpired) CQRs remain in circulation (otherwise verifiers won't be able to validate them).

#### Issuer key revocation

If an issuer key is compromised, the issuer SHALL delete the private key and immediately remove the corresponding public key from the published JWK set (verifiers will from now on reject CQRs issued using that key). The issuer then generates a new key pair.

### Claim QR content

The payload of a Claim QR is a [JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519) (JWT). The JWT has the following requirements:

* SHALL have an `iss` claim containing the issuer URL `[ISSUER_URL]`
* SHALL have a `cqv` claim containing the CQR specification version; currently this is `0.1`
* MAY have a `claimDigests` object containing claims that can be selectively disclosed by the holder; see the [Selective Disclosure]() section
Various application-specific claims can be encoded into the JWT, including the standard ones for validity period (the not-before start time `nbf` and the expiration time `exp`).

### Claim QR issuance

To issue a CQR, the issuer takes the input JWT, makes sure its issuer URL `[ISSUER_URL]` is specified as the `iss` claim, sets the token's metadata if any (`nbf`, `exp`), then the issuer
1. converts the payload into a minified JSON string (without spaces and newlines),
2. compresses the payload string using the DEFLATE algorithm (see [RFC 1951]((https://datatracker.ietf.org/doc/html/rfc1951)); this should be "raw" DEFLATE compression, omitting any zlib or gz headers),
3. creates a compact [JSON Web Signature](https://datatracker.ietf.org/doc/html/rfc7515) (JWS) using the its private signing key, using the compressed payload and setting the JWS header properties,
  * `alg: "ES256"`,
  * `zip: "DEF"`,
  * `kid` equal to the base64url-encoded (see [section 5 of RFC 4648](https://datatracker.ietf.org/doc/html/rfc4648#section-5)) SHA-256 JWK Thumbprint of the key (see [RFC 7638](https://datatracker.ietf.org/doc/html/rfc7638))
4. generates a Quick Response (QR) code of maximum version (size) 22, containing two segments:
  * a `byte` mode segment containing the string `cqr:/`
  * a `numeric` mode segment containing the compact JWS. Each character "c" of the JWS is converted into a sequence of two digits as by taking Ord(c)-45 and treating the result as a two-digit base ten number. For example, 'X' is encoded as 43, since Ord('X') is 88, and 88-45 is 43
5. creates a QR code image from the generated QR code text.

The issuer makes the QR code image available to the holder.

### Claim QR holding

A CQR is a bearer token, meaning there is no private key associated with the credential. It can be printed and stored physically (e.g., on paper) or digitally (e.g., on a phone). 

### Claim QR presentation

A CQR can be presented to any verifier by simply showing the QR code image (digitally or on paper). A verifier can validate the CQR by
1. parsing the QR code image into a QR code text, validating the `cqr:/` header, and decoding the numeric encoding into a JWS,
2. peaking into the JWS payload to extract the `iss` claim encoding the issuer URL `[ISSUER_URL]`,
3. downloading the JWK set from `[ISSUER_URL]/.well-known/jwks.json` (unless the verifier has a recent cached copy), and extracting the public JWK with `kid` matching the JWS's `kid` header,
4. verifying the JWS using the issuer public JWK, returning the payload if valid,
5. inflating the payload to recover the encoded JWT 

Verifiers should only accept CQR from issuers they trust. Trust establishment is application specific. An application could setup a trust directory, similar to the [VCI directory](https://github.com/the-commons-project/vci-directory/) for SHCs.

### Issuer revocation

If an issuer key is compromised, the issuer SHALL remove it from its published JWK set. All issued CQRs issued using that key will from then on be invalid.

### Claim QR revocation

There is no defined mechanism to revoke a specific CQR in this version. Application profiles can adopt various mechanisms to achieve this, including [the one defined in the SHC framework](https://spec.smarthealth.cards/#revocation).

## Differences with the SHC framework

SHCs are meant to encode medical data, using the [FHIR](https://www.hl7.org/fhir/) standard, as opposed to general claims as it is done in this project. The main differences with the SHC framework [specification](https://spec.smarthealth.cards/) are:

* **No VC**: for simplicity, the claims are encoded directly in a JWT, and not in a Verifiable Credential object. In the SHC framework, the VC property simply acts as a shell for the FHIR bundle.
* **No QR chunking**: SHCs can be split across multiple QR codes. This feature hasn't seen much adoption in practice, so this project doesn't make use of it. Application-specific methods can instead be used to split a payload across multiple QR codes, if needed.
* **No X.509 extension**: issue keys can be tied to a X.509 certificate by using the `x5c` property of the JWK. This project doesn't make explicit use of this feature, although an application profile could do so. 
* **cqr header**: SHC QR codes have a `shc` header; this project instead use the header `cqr` (for Claim QR).
* **CQR expiration**: SHCs express medical facts that do not expire, therefore SHCs do not contain an expiration date. CQRs, on the other hand, can encode any type of entitlements, and therefore an expiration date (using the JWT `exp` claim) can be present for many use cases.
* **No stand-alone file**: CQR are only available in the form of a QR code, there is no equivalent to a `.smart-health-card` file.

## Extensions

This initial release reuses as much of the SHC framework as possible, by design. Given the more general scope of CQR, however, some design decisions might be revisited for different use cases. These might be explored in future versions.

* **Supported signature algorithms**: the only allowed signature algorithm at the moment is ECDSA using the NIST P-256 curve and SHA-256 hash algorithm (the JWS `ES256` algorithm). This simplifies and insures interoperability of implementations, but does not provide cryptographic agility. 
* **Different compression and QR encoding**: the SHC compression and QR encoding rules were optimized for the FHIR bundle payload; a generic JWT payload might benefit from other technical options (including exploring using CBOR data).

## Selective Disclosure

In addition to normal, always-disclosed claims, a set of selectively-disclosable claims can be encoded in a CQR. During issuance, the issuer creates empty `claimDigests` and `claimDdata` objects. For each selectively-disclosable claim (with name `n` and value `v`), the issuer

1. picks a cryptographically-random 8-byte salt `s`,
2. calculates the hash digests `d = SHA-256(s,v)`, where the binary `s` is hashed as-is and the string value `v` is hashed as a UTF8 string,
3. truncates the hash digest by keeping only the first 16 bytes,
4. encodes the truncated digest to base64url,
5. creates a new property in the `claimDigests` object with name `n` and value matching the resulting base64url digest
6. creates a new property in the `claimData` object with name `n` and value `{"s": base64url(s), "v": v}` (an object encoding the base64url encoding of the salt and the claim value)

The following pseudo-code illustrates the hashing procedure (TODO: more?)
```js
const b64Digest = crypto.createHash('sha256').update(s).update(v).digest().subarray(0, 16).toString('base64');+++
```

The `claimDigests` object is added to the JWT object with a property key "claimDigests" before being signed (turned into a JWS). The `claimData` object is transformed in a similar manner as the JWT: the issuer
1. converts the `claimData` object into a minified JSON string (without spaces and newlines),
2. compresses the minified string using the DEFLATE algorithm (see [RFC 1951]((https://datatracker.ietf.org/doc/html/rfc1951)); this should be "raw" DEFLATE compression, omitting any zlib or gz headers),
3. base64url-encode the resulting compressed value

The issuer then creates a JWS-with-appendix by appending the resulting string as a 4th compact JWS part. The JWS-with-appendix (with the form `[HEADER].[PAYLOAD].[SIGNATURE].[CLAIMDATA]`) can then be encoded into a QR code normally. 

To verify a CQR with a claim data appendix, the verifier extracts the 4th part of the JWS-with-appendix, verifies the 3-part JWS normally (outputting a JWT containing a `claimDigests` object), base64url-decodes and decompresses (inflates) the 4th part into a `claimData` object. The verifier then, for each claim `n` with digest `d` (from the `claimDigests` object), salt `s` and value `v` (from the `claimData` object), verifies that `d = base64url(SHA-256(s,v)[0..16])` (using the same formatting rules as above).

**NOTE**: The JWS with appendix could have been replaced with a flattened JSW with unprotected header, but we opted for a minimal approach to avoid the lengthy keywords.


## Glossary

* **Claim**: An attribute or statement 
* **CQR**: Claim QR, a JWT encoded into a QR code, as specified in this document
* **JWK**: JSON Web Key, see [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)
* **JWKS**: JSON Web Key Set, a set of JWKs, see [section 5 of RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517#section-5)
* **JWS**: JSON Web Signature, see [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)
* **JWT**: JSON Web Tokens, see [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)
* **SHC**: SMART Health Card, see https://smarthealth.cards/

## Example

This section provides a sample CQR issuance.

### Issuer setup

The issuer, identified as `https://example.org/cqr`, generates its key pair. It keeps its private key secret

```JSON
{
    "kty": "EC",
    "crv": "P-256",
    "x": "gXA--qt2vKqVtBIZHagdLNMOqdEqQ7ckLUYhDea_GRM",
    "y": "C8xyswYTfEEd9JVUqsBOnGSN-hX3C0uBIlHpV3mIf3g",
    "d": "EMrMf-cwOC2olJjfyoQI3JfqvYD_fyxGzyVfkSenfQI",
    "kid": "trmyrXpqXKBZNd11uOc5-8V1m3kJ-JTpMxlw_ZszBYU",
    "use": "sig",
    "alg": "ES256"
}
```

and publishes its JWK set at `https://example.org/cqr/.well-known/jwks.json`

```JSON
{
    "keys": [
        {
            "kty": "EC",
            "crv": "P-256",
            "x": "gXA--qt2vKqVtBIZHagdLNMOqdEqQ7ckLUYhDea_GRM",
            "y": "C8xyswYTfEEd9JVUqsBOnGSN-hX3C0uBIlHpV3mIf3g",
            "kid": "trmyrXpqXKBZNd11uOc5-8V1m3kJ-JTpMxlw_ZszBYU",
            "use": "sig",
            "alg": "ES256"
        }
    ]
}
```

### Claim QR issuance

1. Given the following JWT:

```JSON
{
    "iss": "https://example.org/cqr",
    "nbf": 1648226603.76,
    "cqv": "0.1",
    "given_name": "First",
    "middle_name": "Middle",
    "family_name": "Last",
    "https://example.org/custom": "value"
}
```

2. The issuer deflates the minified JWT string:

```
6DCD410E82301005D0BBCC9AB480A69A1EC0959EC15418B049A740A7341AE3DD9D90B07339EFFF9FF98067060BCF9C67B65AE3CBD11C504D69D4DD92A082F818C036E6786E5B63EA833A990ABAA5C8A6568DE4A32F18EFD1110A5D7CE22C48BEEF03EE7ADB2EE1C1910FEF9DAF6EEBFE7DBD729E483AC58515E1FB03
```


3. The issuer creates the compact JWS:

```
eyJhbGciOiJFUzI1NiIsInppcCI6IkRFRiIsImtpZCI6InRybXlyWHBxWEtCWk5kMTF1T2M1LThWMW0za0otSlRwTXhsd19ac3pCWVUifQ.bc1BDoIwEAXQu8yatICmmh7AlZ7BVBiwSadApzQa492dkLBzOe__n_mAZwYLz5xntlrjy9EcUE1p1N2SoIL4GMA25nhuW2PqgzqZCrqlyKZWjeSjLxjv0REKXXziLEi-7wPuetsu4cGRD--dr27r_n29cp5IOsWFFeH7Aw.PZX_aafUfmLFL8NDLGXjTToiGyfdqMxYf54FYoOUO-24P0zcerCXiDsMCWaIEOmkVkVcPDPylHQhTuiPjyLMwQ
```

4. The issuer creates the QR text:

```
cqr:/567629595326546034602925407728043360287028656767542228092862372537602870286471674522280928653776534363764227217542247122426208623239250439053204313959423242037752036671386337743943597055041252540667224241406057360153540421236628742420433672117652712822646459102063451021412160743852552067773652071205556231217734565050655064204574443177087565716369617612245440240467043305386628310726322005086559724205356858776845226968637630454261563861317561730337243043437760312460001074357256717072075426372300005569051069506505125467082834704225255627102074013545435052525740576431253111332331264361393966602676575568327544570807254466344034000507350377545669224360237032224252282434646241624154352335766327365939726035617631327436
```

5. The issuer creates the QR image:

![example QR code](img/example_qr.png)

### Claim QR issuance with selective disclosure

1. Given the following JWT:

```JSON
{
    "iss": "https://example.org/cqr",
    "nbf": 1648226603.76,
    "cqv": "0.1"
}
```

and set of disclosable claims:

```JSON
{
    "given_name": "First",
    "middle_name": "Middle",
    "family_name": "Last",
    "https://example.org/custom": "value"
}
```
2. The issuer calculates a claims data object,

```JSON
{
    "given_name": { "s": "bAPrA8L8mdg=", "v": "First" },
    "middle_name": { "s": "Sf0YvpT8iNE=", "v": "Middle" },
    "family_name": { "s": "Cdqx+xckLog=", "v": "Last" },
    "https://example.org/custom": { "s": "1O1EI4SoLPk=", "v": "value" }
}
```

3. The issuer calculates a `claimDigests` object, and adds it to the JWT

```JSON
{
    "iss": "https://example.org/cqr",
    "nbf": 1648226603.76,
    "cqv": "0.1",
    "claimDigests": {
        "given_name": "vzNFjrTw7Bkr4ysmzRgeZg==",
        "middle_name": "FIL51fAA/nqmnpsOUvRebg==",
        "family_name": "6V8dqTaPvj+bAKNYnpqN7Q==",
        "https://example.org/custom": "D3g0YBAXKB0SAxbA9hfO5w=="
    },
}
```

4. The issuer deflates the minified JWT string:

```
6DCFC90AC2301485E177C956E9E090D6828B141144A9B3583792B6698C36B1696A9CF0DD0D8A3BD7F7FB0FDC27604A81001CEABA54816D931BE66541AC7345ED5456A009449283C0851DBFD582D0695B1E6C82546AD338966BEE6981191F304A546D869E80324DC45E604E0CD18F6878AC56572F3C559DBBE28F05253BDAEF9B8EB32C2BC80F0E4793AE9B23640BC945A9A66BBD20C917E698B3E2FE8370E367728567FAD848D0388A4529236FFE817F7FB8A8FACC4D376853270ED1761C3A4B744B50EF904FBB57D3BD5E6F
```

5. The issuer creates the compact JWS with appendix:

```
eyJhbGciOiJFUzI1NiIsInppcCI6IkRFRiIsImtpZCI6InRybXlyWHBxWEtCWk5kMTF1T2M1LThWMW0za0otSlRwTXhsd19ac3pCWVUifQ.bc_JCsIwFIXhd8lW6eCQ1oKLFBFEqbNYN5K2aYw2sWlqnPDdDYo71_f7D9wnYEqBABzqulSBbZMb5mVBrHNF7VRWoAlEkoPAhR2_1YLQaVsebIJUatM4lmvuaYEZHzBKVG2GnoAyTcReYE4M0Y9oeKxWVy88VZ274o8FJTva75uOsywryA8OR5OumyNkC8lFqaZrvSDJF-aYs-L-g3DjZ3KFZ_rYSNA4ikUpI2_-gX9_uKj6zE03aFMnDtF2HDpLdEtQ75BPu1fTvV5v.T9ABVccI7emTH-f_ZU56h78AScZE5DCdQqha0J0WYmbGUEWB6VDs08ke8dcvyyTKKgcb3sN54urqaiModIjDUw.q1ZKzyxLzYvPS8xNVbKqVipWslJKcgwocrTwschNSbdV0lEqAwq5ZRYVlyjV6ijlZqak5KSiKA9OM4gsKwixyPRzhSn3BasCqU9LzM3MqURR75xSWKFdkZztkw833icRYnpGSUlBsZW-fmpFYm5BTqpeflG6fnJpcUl-Lkyzob-hq6dJcL5PQDZMc1liTinQrloA
```

6. The issuer creates the QR text:

```
cqr:/567629595326546034602925407728043360287028656767542228092862372537602870286471674522280928653776534363764227217542247122426208623239250439053204313959423242037752036671386337743943597055041252540667224241406057360153545029227028742528435955116342095622360466303125212524685333443308300552447405704263686535235523446610045057102312746544246821202177687263382153453253086441216927332510413742662063246266352059370550044431365241705653282940527132076364737252442445277721304126052665662076395437564424073203441266563075424176111141450510076611252939735210087234707674697620113437083472647633622211632568524569733823292500524470003100580623614506302545506944383320076062406728055000584312507230610977240306522532652371250527236731552471361008213572045739734108730139122021415454281056643927005750454008095910112038544524082322553668595203290342446453264024422109412370031162561155547376763930305854530670330807726968526032665528612340740168044530777675317744733538117533415330684160674270632930545874665469397470545933385355410363246820746808453744416376614109606163456852620830386030201234320758703074607576353777593865062152702268401231773206326840373710087538423025556245777162741106066054374465672638406321704542005764672544640821396867565763260957652967544063003162767766530059680955295431083536234532540463603960653669636620
```

7. The issuer creates the QR image:

![example QR code](img/example_selectivedisclosure_qr.png)

# Library

## Setup

Make sure [node.js](https://nodejs.org/) and [npm](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm) are installed on your system; the latest Long-Term Support (LTS) version is recommended for both.

1. Get the source, for example using `git`
```
git clone -b main https://github.com/microsoft/ClaimQR.git
cd ClaimQR
```

2. Build the `npm` package
```
npm install
npm run build
```

3. Optionally, run the unit tests

```
npm test
```

## Usage

This section describes the command-line usage of the library; see the `sample/src/server.ts` for an example to see how to use the API.

### Generate the issuer keys

The issuer, identified by its URL `[ISSUER_URL]`, first needs to create its key pair. The resulting JSON Web Key Set (JWKS) file must be hosted at `[ISSUER_URL]/.well-known/jwks.json`, while the private key must be kept secret.

Using the `npm` command-line:

```
npm run generate-issuer-keys -- --jwksPath jwks.json --privatePath privatekey.json
```

The public key will be added to the JWK set file specified by  `jwksPath` (will be created if it doesn't exist). 

### Issue a Claim QR

The issuer can create a QR code from a JSON Web Token (JWT) containing an `iss` property with the value `[ISSUER_URL]` and a set of application-specific always-disclosed claims (in `jwt.json`), using its private key (in `privatekey.json`), optionally passing a set of selectively-disclosable claims (in `claims.json`).

Using the `npm` command-line:

```
npm run issue-qr -- --privatePath privatekey.json --jwtPath jwt.json --qrPath qr.png [--claimValuesPath claims.json]
```

The resulting QR code image `qr.png` can be used by the user.

### Selective disclosure on a Claim QR

If a Claim QR encodes some selectively-disclosable claims, the holder can update the QR code (in `qr.png`, output to `updated_qr.png`) to only disclose a subset of the claims (`c1`, ..., `ck`) to the verifier. 

Using the `npm` command-line:

```
npm run disclose-claims -- --qrPath qr.png  --outQrPath updated_qr.png --claims c1 ... ck
```

### Verify a Claim QR

Any party can verify a presented QR code (in `qr.png`), and extract the encoded JWT (output to `outjwt.json`). The issuer's public key will be retrieved from the `iss` property in the encoded JWT; optionally, a JWK set (in `jwks.json`) can be passed to the verifier for offline validation. Any selectively-disclosed claims will be added to the output JWT in a `disclosedClaims` object.

Using the `npm` command-line:

```
npm run verify-qr -- --qrPath qr.png --jwtPath outjwt.json [--jwksPath jwks.json]
```

## Sample

The `sample/` folder contains a sample issuer and verifier that can be used to issue and verify a Claim QR.

To setup and deploy the sample, perform the following steps:
```
cd sample
npm install
npm run build
npm run deploy
```

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
