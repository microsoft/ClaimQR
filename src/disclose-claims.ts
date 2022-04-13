// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import fs from 'fs';
import * as jose from 'jose';
import pako from 'pako';
import { QRCodeSegment } from 'qrcode';
import { createQrAsBuffer, createQrAsDataURL, decodeQrFile, jwsToQr, qrToJws } from './qr';
import { parseClaimsData } from './selective-disclosure';

const discloseClaims = async (qrText: string, claims: string[]): Promise<QRCodeSegment[]> => {
    let jws = qrToJws(qrText);

    // extract 4th part containing the claims data
    const parts = jws.split('.');
    if (parts.length !== 4) {
        throw new Error("Error parsing JWS, no claim data found");
    }
    let claimsData = parseClaimsData(parts[3]);
    // remove the undisclosed claims
    let claimNames = Object.keys(claimsData);
    claimNames.forEach(name => {
        if (!claims.includes(name)) {
            delete claimsData[name];
        }
    })
    // re-encode the updated claims data
    const b64claimData = jose.base64url.encode(Buffer.from(pako.deflateRaw(JSON.stringify(claimsData))));
    parts[3] = b64claimData;
    jws = parts.join('.');

    // re-encode the QR
    return jwsToQr(jws);
}

export const discloseClaimsAsBuffer = async (qrText: string, claims: string[]): Promise<Buffer> => {
    const qrSegments = await discloseClaims(qrText, claims);
    const qr = await createQrAsBuffer(qrSegments);
    return qr;
}

export const discloseClaimsAsDataUrl = async (qrText: string, claims: string[]): Promise<string> => {
    const qrSegments = await discloseClaims(qrText, claims);
    const qr = await createQrAsDataURL(qrSegments);
    return qr;
}

export const discloseClaimsFiles = async (type: string, qrPath: string, claims: string[], outQrPath: string): Promise<void> => {
    console.log(`Disclosing claims ${claims} from QR ${qrPath}`);

    if (!fs.existsSync(qrPath)) {
        throw new Error("File not found: " + qrPath);
    }
    const qrText = await decodeQrFile(type, qrPath);
    const qr = await discloseClaimsAsBuffer(qrText, claims);
    fs.writeFileSync(outQrPath, qr);
    console.log(`QR code written to ${outQrPath}`);
}