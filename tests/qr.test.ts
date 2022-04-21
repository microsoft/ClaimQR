// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import fs from 'fs';
import * as jose from 'jose';
import {generateIssuerKeys, generateIssuerKeysFiles} from '../src/generate-issuer-keys';
import {issueQrAsBuffer, issueQrAsDataUrl, issueQrFiles} from '../src/issue-qr';
import {verifyQr, verifyQrFiles} from '../src/verify-qr';
import {discloseClaimsFiles} from '../src/disclose-claims';

const fileEqual = (a: string, b: string): boolean => {return fs.readFileSync(a).equals(fs.readFileSync(b))}

test("Generate issuer keys", async () => {
    const result = await generateIssuerKeys(undefined);
    expect(result.jwks).toBeDefined();
    expect(result.privateJwk).toBeDefined();
});

test("Generate issuer keys -- file API", async () => {
    const privateKeyPath = 'tmp/testPrivateKey.json';
    const jwksPath = 'tmp/testjwks.json';
    await generateIssuerKeysFiles(privateKeyPath, jwksPath);
    expect(fs.existsSync(privateKeyPath)).toBeTruthy();
    expect(fs.existsSync(jwksPath)).toBeTruthy();
});

test("Issue QR as Buffer", async () => {
    const privateString = fs.readFileSync('tests/test_private.json', 'utf8');
    const jwkJson = JSON.parse(privateString) as jose.JWK;

    // read the JWT payload
    const jwtString = fs.readFileSync('tests/test_jwt.json', 'utf8');
    const jwt = JSON.parse(jwtString);

    // issue and write-out QR code
    const qr = await issueQrAsBuffer(jwkJson, jwt, undefined);
    expect(qr).toBeDefined();
});

test("Issue QR as Data URL", async () => {
    const privateString = fs.readFileSync('tests/test_private.json', 'utf8');
    const jwkJson = JSON.parse(privateString) as jose.JWK;

    // read the JWT payload
    const jwtString = fs.readFileSync('tests/test_jwt.json', 'utf8');
    const jwt = JSON.parse(jwtString);

    // issue and write-out QR code
    const qr = await issueQrAsDataUrl(jwkJson, jwt, undefined);
    expect(qr).toBeDefined();
});

test("Issue QR -- file API", async () => {
    const qrPath = 'tmp/qr.png';
    await issueQrFiles('tests/test_private.json', 'tests/test_jwt.json', qrPath, undefined);
    expect(fs.existsSync(qrPath)).toBeTruthy();
});

test("Issue QR as Buffer with selective disclosure", async () => {
    const privateString = fs.readFileSync('tests/test_private.json', 'utf8');
    const jwkJson = JSON.parse(privateString) as jose.JWK;

    // read the JWT payload
    const jwtString = fs.readFileSync('tests/test_seldisc_jwt.json', 'utf8');
    const jwt = JSON.parse(jwtString);

    // read the claim values
    const claimValuesString = fs.readFileSync('tests/test_seldisc_claims.json', 'utf8');
    const claimValues = JSON.parse(claimValuesString);

    // issue and write-out QR code
    const qr = await issueQrAsBuffer(jwkJson, jwt, claimValues);
    expect(qr).toBeDefined();
});

test("Issue QR as Data URL with selective disclosure", async () => {
    const privateString = fs.readFileSync('tests/test_private.json', 'utf8');
    const jwkJson = JSON.parse(privateString) as jose.JWK;

    // read the JWT payload
    const jwtString = fs.readFileSync('tests/test_seldisc_jwt.json', 'utf8');
    const jwt = JSON.parse(jwtString);

    // read the claim values
    const claimValuesString = fs.readFileSync('tests/test_seldisc_claims.json', 'utf8');
    const claimValues = JSON.parse(claimValuesString);

    // issue and write-out QR code
    const qr = await issueQrAsDataUrl(jwkJson, jwt, claimValues);
    expect(qr).toBeDefined();
});

test("Issue QR -- file API with selective disclosure", async () => {
    const qrPath = 'tmp/qr.png';
    await issueQrFiles('tests/test_private.json', 'tests/test_seldisc_jwt.json', qrPath, 'tests/test_seldisc_claims.json');
    expect(fs.existsSync(qrPath)).toBeTruthy();
});

// TODO: add sel. disc. claim

test("Verify QR", async () => {
    const qrTest = fs.readFileSync('tests/test_qr.txt', 'utf-8');
    const jwt = await verifyQr(qrTest, undefined);
    expect(jwt).toBeDefined();
});

test("Verify QR -- file API", async () => {
    await verifyQrFiles('text', 'tests/test_qr.txt', 'tmp/outjwt.json', undefined);
});

test("Verify QR -- file API w/ offline JWKS", async () => {
    await verifyQrFiles('text', 'tests/test_qr.txt', 'tmp/outjwt.json', 'tests/.well-known/jwks.json');
});

test("Test end-to-end", async () => {
    const privateKeyPath = 'tmp/e2eprivate.json';
    const jwksPath = 'tmp/e2ejwks.json';
    const jwtPath = 'tests/test_jwt.json';
    const qrPath = 'tmp/e2eqr.png';
    const outJwtPath = 'tmp/e2eOutJwt.json';
    await generateIssuerKeysFiles(privateKeyPath, jwksPath);
    await issueQrFiles(privateKeyPath, jwtPath, qrPath, undefined);
    await verifyQrFiles('image', qrPath, outJwtPath, jwksPath);
    expect(fileEqual(jwtPath,outJwtPath)).toBeTruthy();
});

test("Test end-to-end with selective disclosure", async () => {
    const privateKeyPath = 'tmp/e2eSDprivate.json';
    const jwksPath = 'tmp/e2eSDjwks.json';
    const jwtPath = 'tests/test_seldisc_jwt.json';
    const claimsPath = 'tests/test_seldisc_claims.json';
    const qrPath = 'tmp/e2eSDqr.png';
    const outJwtPath = 'tmp/e2eSDOutJwt.json';
    const selDiscQrPath = 'tmp/e2eSDupdatedQr.png';
    const outUpdatedJwtPath = 'tmp/e2eSDUpdatedOutJwt.json';
    const claims = ['middle_name', 'https://example.org/custom'];
    await generateIssuerKeysFiles(privateKeyPath, jwksPath);
    await issueQrFiles(privateKeyPath, jwtPath, qrPath, claimsPath);
    await verifyQrFiles('image', qrPath, outJwtPath, jwksPath);
    await discloseClaimsFiles('image', qrPath, claims, selDiscQrPath);
    await verifyQrFiles('image', selDiscQrPath, outUpdatedJwtPath, jwksPath);
    const outUpdatedJwtString = fs.readFileSync(outUpdatedJwtPath, 'utf8');
    const outUpdatedJwt = JSON.parse(outUpdatedJwtString);
    // check claim values were correctly disclosed
    expect(outUpdatedJwt.disclosedClaims).toBeTruthy();
    Object.keys(outUpdatedJwt.disclosedClaims).forEach(claim => {
        expect(outUpdatedJwt.disclosedClaims[claim]).toBeTruthy();
    });
});


// error cases

test("CQR with invalid signature", async () => {
    await expect(verifyQrFiles('image', 'tests/qr_invalid_sig.png', 'tmp/outjwt.json', 'tests/.well-known/jwks.json')).rejects.toThrow();
});

test("Expired CQR", async () => {
    await expect(verifyQrFiles('image', 'tests/test_expired_qr.png', 'tmp/outjwt.json', 'tests/.well-known/jwks.json')).rejects.toThrow();
});

test("Not yet valid CQR", async () => {
    await expect(verifyQrFiles('image', 'tests/test_notyetvalid_qr.png', 'tmp/outjwt.json', 'tests/.well-known/jwks.json')).rejects.toThrow();
});
