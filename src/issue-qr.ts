// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import fs from 'fs';
import * as jose from 'jose';
import pako from 'pako';
import QrCode, { QRCodeSegment } from 'qrcode';

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

export const issueQr = async (jwkJson: jose.JWK, jwt: any): Promise<Buffer> => {
    try {
        const bodyString = JSON.stringify(jwt); // needed?
        const payload = pako.deflateRaw(bodyString);

        const kid = jwkJson.kid;
        if (!kid) {
            throw new Error("JWK doesn't have a kid");
        }
        const jwk = await jose.importJWK(jwkJson, 'ES256');

        const jws = await new jose.CompactSign(payload)
        .setProtectedHeader({ alg: 'ES256', zip: 'DEF', kid: kid })
        .sign(jwk);

        const numericQR = toNumericQr(jws);

        const qr = await QrCode.toBuffer(numericQR, {type: 'png', errorCorrectionLevel: 'low'});

        return qr;
    } catch (err) {
        throw new Error(`Can't issue QR code: ${err as string}`);
    }
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
    const qr = await issueQr(jwkJson, jwt);
    fs.writeFileSync(qrPath, qr);
    console.log(`QR code written to ${qrPath}`);
}
