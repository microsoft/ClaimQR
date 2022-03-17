// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import fs from 'fs';
import * as jose from 'jose';
import {generateIssuerKeys, generateIssuerKeysFiles} from '../src/generate-issuer-keys';
import {issueQr, issueQrFiles} from '../src/issue-qr';
import {verifyQr, verifyQrFiles} from '../src/verify-qr';

test("Generate issuer keys", async () => {
    const result = await generateIssuerKeys(undefined);
    expect(result.jwks).toBeDefined();
    expect(result.privateJwk).toBeDefined();
});

test("Generate issuer keys -- file API", async () => {
    const privateKeyPath = 'tmp/testPrivateKey.json';
    const jwksPath = 'tmp/testjwks.json'; // TODO: delete
    await generateIssuerKeysFiles(privateKeyPath, jwksPath);
    expect(fs.existsSync(privateKeyPath)).toBeTruthy();
    expect(fs.existsSync(jwksPath)).toBeTruthy();
});

test("Issue QR", async () => {
    const privateString = fs.readFileSync('tests/test_private.json', 'utf8');
    const jwkJson = JSON.parse(privateString) as jose.JWK;

    // read the JWT payload
    const jwtString = fs.readFileSync('tests/test_jwt.json', 'utf8');
    const jwt = JSON.parse(jwtString);

    // issue and write-out QR code
    const qr = await issueQr(jwkJson, jwt);
    expect(qr).toBeDefined();
});

test("Issue QR -- file API", async () => {
    const qrPath = 'tmp/qr.png';
    await issueQrFiles('tests/test_private.json', 'tests/test_jwt.json', qrPath);
    expect(fs.existsSync(qrPath)).toBeTruthy();
});

test("Verify QR", async () => {
    const qrTest = fs.readFileSync('tests/test_qr.txt', 'utf-8');
    const jwt = await verifyQr(qrTest, undefined);
    expect(jwt).toBeDefined();
});

test("Verify QR -- file API", async () => {
    await verifyQrFiles('text', 'tests/test_qr.txt', 'tmp/outjwt.json', undefined);
});

test("Verify QR -- file API w/ offline JWKS", async () => {
    await verifyQrFiles('text', 'tests/test_qr.txt', 'tmp/outjwt.json', 'tests/test_jwks.json');
});

test("Test end-to-end", async () => {
    const privateKeyPath = 'tmp/e2eprivate.json';
    const jwksPath = 'tmp/e2ejwks.json'; // TODO: delete
    const jwtPath = 'tests/test_jwt.json';
    const qrPath = 'tmp/e2eqr.png';
    const outJwtPath = 'tmp/e2eOutJwt.json';
    await generateIssuerKeysFiles(privateKeyPath, jwksPath);
    await issueQrFiles(privateKeyPath, jwtPath, qrPath);
    await verifyQrFiles('image', qrPath, outJwtPath, jwksPath);
    // TODO: check file match
});

// error cases

/* TODO
test("Verify invalid QR", async () => {
    expect(await verifyQrFiles('image', 'tests/qr_invalid_sig.png', 'tmp/outjwt.json', undefined)).toThrow();
});
*/