// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import fs from 'fs';
import * as jose from 'jose';
import pako from 'pako';
import QrCode, { QRCodeSegment } from 'qrcode';

const VERBOSE_OUTPUT = false; // set to true to generate the spec example

const SMALLEST_B64_CHAR_CODE = 45; // "-".charCodeAt(0) === 45
const toNumericQr = (jws: string): QRCodeSegment[] => [
  { data: 'cqr:/', mode: 'byte' },
  {
    data: jws
      .split('')
      .map((c) => c.charCodeAt(0) - SMALLEST_B64_CHAR_CODE)
      .flatMap((c) => [Math.floor(c / 10), c % 10])
      .join(''),
    mode: 'numeric',
  },
];

const issueQrAsText = async (jwkJson: jose.JWK, jwt: any): Promise<QRCodeSegment[]> => {
    try {
        const kid = jwkJson.kid;
        if (!kid) {
            throw new Error("JWK doesn't have a kid");
        }

        const bodyString = JSON.stringify(jwt);
        const payload = pako.deflateRaw(bodyString);
        if (VERBOSE_OUTPUT) console.log(Buffer.from(payload).toString("hex").toUpperCase());

        const jwk = await jose.importJWK(jwkJson, 'ES256');
        const jws = await new jose.CompactSign(payload)
        .setProtectedHeader({ alg: 'ES256', zip: 'DEF', kid: kid })
        .sign(jwk);
        if (VERBOSE_OUTPUT) console.log(jws);

        const numericQR = toNumericQr(jws);
        if (VERBOSE_OUTPUT) console.log(numericQR);

        return numericQR;
    } catch (err) {
        throw new Error(`Can't issue QR code: ${err as string}`);
    }
}

export const issueQrAsBuffer = async (jwkJson: jose.JWK, jwt: any): Promise<Buffer> => {
    const numericQR = await issueQrAsText(jwkJson, jwt);
    const qr = await QrCode.toBuffer(numericQR, {type: 'png', errorCorrectionLevel: 'low'});
    return qr;
}

export const issueQrAsDataUrl = async (jwkJson: jose.JWK, jwt: any): Promise<string> => {
    const numericQR = await issueQrAsText(jwkJson, jwt);
    const qr = await QrCode.toDataURL(numericQR, { errorCorrectionLevel: 'low' });
    return qr;
}

export const issueQrFiles = async (privatePath: string, jwtPath: string, qrPath: string): Promise<void> => {
    console.log(`Issuing QR from the JWT ${jwtPath} using the private key ${privatePath}`);

    if (!fs.existsSync(privatePath)) {
        throw new Error("File not found : " + privatePath);
    }
    if (!fs.existsSync(jwtPath)) {
        throw new Error("File not found : " + jwtPath);
    }

    // read the private key
    const privateString = fs.readFileSync(privatePath, 'utf8');
    const jwkJson = JSON.parse(privateString) as jose.JWK;

    // read the JWT payload
    const jwtString = fs.readFileSync(jwtPath, 'utf8');
    const jwt = JSON.parse(jwtString);

    // issue and write-out QR code
    const qr = await issueQrAsBuffer(jwkJson, jwt);
    fs.writeFileSync(qrPath, qr);
    console.log(`QR code written to ${qrPath}`);
}
