// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import sharp from 'sharp';
import jsQR from 'jsqr';
import fs from 'fs';
import QrCode, { QRCodeSegment } from 'qrcode';

const SMALLEST_B64_CHAR_CODE = 45; // "-".charCodeAt(0) === 45
const toNumericSegment = (jws: string): QRCodeSegment => {
    return {
      data: jws
        .split('')
        .map((c) => c.charCodeAt(0) - SMALLEST_B64_CHAR_CODE)
        .flatMap((c) => [Math.floor(c / 10), c % 10])
        .join(''),
      mode: 'numeric',
    }
}

export const jwsToQr = (jws: string): QRCodeSegment[] => {
    return [
        { data: 'cqr:/', mode: 'byte' },
        toNumericSegment(jws)
    ]
}

export const qrToJws = (cqr: string): string => {
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

export const decodeQr = (data: Uint8ClampedArray, width: number, height: number): string => {
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

export const decodeQrFile = async (type: string, qrPath: string): Promise<string> => {
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

    return qrText;
}

export const createQrAsBuffer = async (qrSegments: QRCodeSegment[]): Promise<Buffer> => {
    return await QrCode.toBuffer(qrSegments, {type: 'png', errorCorrectionLevel: 'low'});
}

export const createQrAsDataURL = async (qrSegments: QRCodeSegment[]): Promise<string> => {
    return await QrCode.toDataURL(qrSegments, { errorCorrectionLevel: 'low' });
}