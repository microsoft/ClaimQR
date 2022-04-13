// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import fs from 'fs';
import * as jose from 'jose';
import pako from 'pako';
import * as crypto from 'crypto';
import {ClaimData, parseClaimsData} from './selective-disclosure'
import { decodeQrFile, qrToJws } from './qr';

interface JWSPayload {
    iss: string,
    cqv: string,
    nbf?: number,
    exp?: number,
    claimDigests?: any
    disclosedClaims?: any
}

const validateJws = async (jws: string, jwksJson: jose.JSONWebKeySet | undefined): Promise<JWSPayload> => {
    // split JWS into header[0], payload[1], sig[2], and optionally claimData[3]
    const parts = jws.split('.');
    let claimsData = undefined;
    if (parts.length === 4) {
        // extract the 4th part with the claim salts
        jws = parts.slice(0,3).join('.');
        claimsData = parseClaimsData(parts[3]);
    } else if (parts.length !== 3) {
        throw new Error("Error parsing JWS");
    }

    // check payload
    let jWSPayload: JWSPayload;
    try {
        const b64DecodedPayloadBuffer = Buffer.from(parts[1], 'base64');
        // extract the utf8 bytes
        const inflatedPayloadBuf = pako.inflateRaw(b64DecodedPayloadBuffer);
        if (!inflatedPayloadBuf) throw new Error("inflateRaw failed");
        const payload = Buffer.from(inflatedPayloadBuf).toString();
        if (!payload) throw new Error("inflated payload can't be parsed as a string");
        jWSPayload = JSON.parse(payload) as JWSPayload;
        if (!jWSPayload) throw new Error("payload can't be parsed as a JWS payload");
    } catch (err) {
        throw new Error(`Error decode the JWS payload: ${err}`);
    }

    // retrieve the issuer key
    const iss = (jWSPayload.iss);
    if (!iss) {
        throw new Error("Missing iss field from JWS header");
    }
    // TODO: check if issuer is trusted here?
    let jwks;
    if (jwksJson) {
        jwks = jose.createLocalJWKSet(jwksJson);
    } else {
        let issURL;
        try {
            const issURL = iss + '/.well-known/jwks.json';
            jwks = jose.createRemoteJWKSet(new URL(issURL));
        } catch (err) {
            throw new Error(`Error downloading the issuer key from ${issURL}: ${err}`);
        }
    }
    try {
        const result = await jose.compactVerify(jws, jwks);
    } catch (err) {
        throw new Error(`Error validating signature: ${err}`);
    }

    // only keep the disclosed claims
    if (claimsData) {
        console.log(claimsData);
        const disclosedClaimNames:string[] = Object.keys(claimsData);
        const claimDigests = jWSPayload.claimDigests;
        let disclosedClaims = {};
        for (let i = 0; i < disclosedClaimNames.length; i++) {
            const name = disclosedClaimNames[i];
            let value;
            let salt;
            let digest;
            if (claimDigests.hasOwnProperty(name) && claimDigests[name as any] !== undefined) {
                digest = claimDigests[name as any];
            }
            if (claimsData.hasOwnProperty(name) && claimsData[name as any] !== undefined) {
                salt = Buffer.from((claimsData[name as any] as ClaimData).s, 'base64');
                value = (claimsData[name as any] as ClaimData).v;
            }
            if (salt && value && digest) { // TODO: error if you can't
                const digest2 = crypto.createHash('sha256').update(salt).update(value).digest().subarray(0, 16).toString('base64');
                if (digest !== digest2) {
                    throw new Error('Invalid digest for claim ${name}');
                }
            }
            Object.defineProperty(disclosedClaims, name, {value: value, enumerable: true});
        }
        Object.defineProperty(jWSPayload, "disclosedClaims", {value: disclosedClaims, enumerable: true});
    }

    return jWSPayload;
}


const getDate = (time: number) => {
    const date = new Date();
    date.setTime(time * 1000); // convert seconds to milliseconds
    return date;
}

export const verifyQr = async (qrText: string, jwks: jose.JSONWebKeySet | undefined): Promise<JWSPayload> => {
    try {
        // extract the JWS
        let jws = qrToJws(qrText);

        // validate the JWS and extract the JWT
        const jwt = await validateJws(jws, jwks);
        
        // validate validity period
        const now = new Date();
        if (jwt.nbf) {
            const nbf = getDate(jwt.nbf);
            if (nbf && nbf > now) {
                throw new Error(`CQR not yet valid: 'nbf': ${nbf}, now: ${now}`);
            }
        }
        if (jwt.exp) {
            const exp = getDate(jwt.exp);
            if (exp && now > exp) {
                throw new Error(`CQR is expired: 'exp': ${exp}, now: ${now}`);
            }
        }

        return jwt;
    } catch (err) {
        throw new Error(`Can't verify QR code: ${err as string}`);
    }
}

export const verifyQrFiles = async (type: string, qrPath: string, jwtPath: string, jwksPath: string | undefined): Promise<void> => {
    console.log(`Verifying QR ${type} from ${qrPath}`);

    if (!fs.existsSync(qrPath)) {
        throw new Error("File not found: " + qrPath);
    }

    let jwks: jose.JSONWebKeySet | undefined;
    if (jwksPath) {
        if (!fs.existsSync(jwksPath)) {
            throw new Error("File not found: " + jwksPath);
        }
        const jwksBytes = fs.readFileSync(jwksPath, 'utf8');
        jwks = JSON.parse(jwksBytes) as jose.JSONWebKeySet;
    }

    const qrText = await decodeQrFile(type, qrPath);

    const jwt = await verifyQr(qrText, jwks);

    // output the JWT
    fs.writeFileSync(jwtPath, JSON.stringify(jwt, null, 4));
    console.log(`JWT written to ${jwtPath}`);
}
