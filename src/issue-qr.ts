// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import fs from 'fs';
import * as jose from 'jose';
import pako from 'pako';
import { QRCodeSegment } from 'qrcode';
import { createClaimDigestsObject } from './selective-disclosure';
import { createQrAsBuffer, createQrAsDataURL, jwsToQr } from './qr';

const VERBOSE_OUTPUT = true; // set to true to generate the spec example

const issueQrAsText = async (jwkJson: jose.JWK, jwt: any, claimValues: any | undefined): Promise<QRCodeSegment[]> => {
    try {
        const kid = jwkJson.kid;
        if (!kid) {
            throw new Error("JWK doesn't have a kid");
        }

        let b64claimData: string = '';
        if (claimValues) {
            const result = createClaimDigestsObject(claimValues);
            console.log(result);
            Object.defineProperty(jwt, "claimDigests", {value: result.digests, enumerable: true});
            b64claimData = jose.base64url.encode(Buffer.from(pako.deflateRaw(JSON.stringify(result.data))));
        }

        const bodyString = JSON.stringify(jwt);
        const payload = pako.deflateRaw(bodyString);
        if (VERBOSE_OUTPUT) console.log(Buffer.from(payload).toString("hex").toUpperCase());

        const jwk = await jose.importJWK(jwkJson, 'ES256');
        let jws = await new jose.CompactSign(payload)
        .setProtectedHeader({ alg: 'ES256', zip: 'DEF', kid: kid })
        .sign(jwk);
        if (b64claimData) {
            jws = jws.concat('.', b64claimData);
        }
        if (VERBOSE_OUTPUT) console.log(jws);

        const numericQR = jwsToQr(jws);
        if (VERBOSE_OUTPUT) console.log(numericQR);

        return numericQR;
    } catch (err) {
        throw new Error(`Can't issue QR code: ${err as string}`);
    }
}

export const issueQrAsBuffer = async (jwkJson: jose.JWK, jwt: any, claimValues: any | undefined): Promise<Buffer> => {
    const qrSegments = await issueQrAsText(jwkJson, jwt, claimValues);
    const qr = await createQrAsBuffer(qrSegments);
    return qr;
}

export const issueQrAsDataUrl = async (jwkJson: jose.JWK, jwt: any, claimValues: any | undefined): Promise<string> => {
    const qrSegments = await issueQrAsText(jwkJson, jwt, claimValues);
    const qr = await createQrAsDataURL(qrSegments);
    return qr;
}

export const issueQrFiles = async (privatePath: string, jwtPath: string, qrPath: string, claimValuesPath: string | undefined): Promise<void> => {
    console.log(`Issuing QR from the JWT ${jwtPath} using the private key ${privatePath}`);
    if (claimValuesPath) console.log(`Encoding selectively-disclosable claims from ${claimValuesPath}`);

    if (!fs.existsSync(privatePath)) {
        throw new Error("File not found : " + privatePath);
    }
    if (!fs.existsSync(jwtPath)) {
        throw new Error("File not found : " + jwtPath);
    }
    if (claimValuesPath && !fs.existsSync(claimValuesPath)) {
        throw new Error("File not found : " + jwtPath);
    }

    // read the private key
    const privateString = fs.readFileSync(privatePath, 'utf8');
    const jwkJson = JSON.parse(privateString) as jose.JWK;

    // read the JWT payload
    const jwtString = fs.readFileSync(jwtPath, 'utf8');
    const jwt = JSON.parse(jwtString);

    // read the ClaimDigests payload
    let claimDigests;
    if (claimValuesPath) {
        const claimDigestsString = fs.readFileSync(claimValuesPath, 'utf8');
        claimDigests = JSON.parse(claimDigestsString);
    }

    // issue and write-out QR code
    const qr = await issueQrAsBuffer(jwkJson, jwt, claimDigests);
    fs.writeFileSync(qrPath, qr);
    console.log(`QR code written to ${qrPath}`);
}
