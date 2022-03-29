// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import fs from 'fs';
import * as jose from 'jose';
import pako from 'pako';
import jsQR from 'jsqr';
import sharp from 'sharp';

interface JWSPayload {
    iss: string,
    cqv: string,
    nbf?: number,
    exp?: number,
}

const validateJws = async (jws: string, jwksJson: jose.JSONWebKeySet | undefined): Promise<JWSPayload> => {
    // split JWS into header[0], payload[1], sig[2]
    const parts = jws.split('.');
    if (parts.length !== 3) {
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

   return jWSPayload;
}

const decodeQr = (data: Uint8ClampedArray, width: number, height: number): string => {
        // decode QR
        let code = jsQR(data, width, height);
        if (!code) {
            throw new Error("Can't parse QR code");
        }
        if (code?.version > 22) {
            console.log(`QR has version ${code.version}, exceeding max of 22`);
        }
        if (!code.chunks || code.chunks.length !== 2) {
            throw new Error(`Wrong number of segments in QR code: found ${code.chunks.length}, expected 2`);
        } 
        if (code.chunks[0].type !== 'byte') {
            throw new Error(`Wrong encoding mode for first QR segment: found ${code.chunks[0].type}, expected "byte"`);
        }
        if (code.chunks[1].type !== 'numeric') {
            throw new Error(`Wrong encoding mode for second QR segment: found ${code.chunks[0].type}, expected "numeric"`);
        }

        return code.data;
}

const qrToJws = (cqr: string): string => {
    const qrHeader = 'cqr:/';
    const bodyIndex = cqr.lastIndexOf('/') + 1;
    const b64Offset = '-'.charCodeAt(0);
    const digitPairs = cqr.substring(bodyIndex).match(/(\d\d?)/g);

    if (digitPairs == null || digitPairs[digitPairs.length - 1].length == 1) {
        throw new Error("Invalid numeric QR code, can't parse digit pairs.");
    }

    // since source of numeric encoding is base64url-encoded data (A-Z, a-z, 0-9, -, _, =), the lowest
    // expected value is 0 (ascii(-) - 45) and the biggest one is 77 (ascii(z) - 45), check that each pair
    // is no larger than 77
    if (Math.max(...digitPairs.map(d => Number.parseInt(d))) > 77) {
        throw new Error("Invalid numeric QR code, one digit pair is bigger than the max value 77.");
    }

    // breaks string array of digit pairs into array of numbers: 'cqr:/123456...' = [12,34,56,...]
    const jws: string = digitPairs
        // for each number in array, add an offset and convert to a char in the base64 range
        .map((c: string) => String.fromCharCode(Number.parseInt(c) + b64Offset))
        // merge the array into a single base64 string
        .join('');

    return jws;
}

const getDate = (time: number) => {
    const date = new Date();
    date.setTime(time * 1000); // convert seconds to milliseconds
    return date;
}

export const verifyQr = async (qrText: string, jwks: jose.JSONWebKeySet | undefined): Promise<JWSPayload> => {
    try {
        // extract the JWS
        const jws = qrToJws(qrText);

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
        throw new Error("File not found : " + qrPath);
    }

    let jwks: jose.JSONWebKeySet | undefined;
    if (jwksPath && fs.existsSync(jwksPath)) {
        const jwksBytes = fs.readFileSync(jwksPath, 'utf8');
        jwks = JSON.parse(jwksBytes) as jose.JSONWebKeySet;
    }

    let qrText: string;
    if (type === 'image') {
        // parse and decode the QR image
        const s = sharp(qrPath);
        const { data, info } = await s.raw().ensureAlpha().toBuffer({ resolveWithObject: true });
        qrText = decodeQr(new Uint8ClampedArray(data.buffer), info.width, info.height);
    } else if (type === 'text') {
        qrText = fs.readFileSync(qrPath, 'utf-8');
    } else {
        throw new Error(`Invalid type ${type}, expected "image" or "text"`);
    }

    const jwt = await verifyQr(qrText, jwks);

    // output the JWT
    fs.writeFileSync(jwtPath, JSON.stringify(jwt, null, 4));
    console.log(`JWT written to ${jwtPath}`);
}
