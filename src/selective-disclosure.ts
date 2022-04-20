// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import * as crypto from 'crypto';
import pako from 'pako';
import * as jose from 'jose';

export interface ClaimDigests {

}

export interface ClaimData {
    s: string; // salt
    v: string; // value
}

export interface ClaimDigestResults {
    data: any; // how to specify multiple keys with ClaimData values
    digests: ClaimDigests;
}

export const parseClaimsData = (encodedClaimsData: string): any => {
    const b64DecodedClaimsData = Buffer.from(encodedClaimsData, 'base64');
    const inflatedClaimsData = pako.inflateRaw(b64DecodedClaimsData);
    const claimsDataString = Buffer.from(inflatedClaimsData).toString();
    const claimsData = JSON.parse(claimsDataString);
    return claimsData;
}

export const createClaimDigestsObject = (claimValues: any): ClaimDigestResults => {
    let data = {};
    let claimDigests = {};
    const names = Object.keys(claimValues);
    const values: string[] = Object.values(claimValues);
    const salts: Buffer[] = names.map(v => crypto.randomBytes(8));
    for (let i = 0; i < names.length; i++) {
        const claimData = {
            s: jose.base64url.encode(salts[i]),
            v: values[i]
        }
        Object.defineProperty(data, names[i], {value: claimData, enumerable: true});
        const b64Digest = jose.base64url.encode(crypto.createHash('sha256').update(salts[i]).update(values[i]).digest().subarray(0, 16));
        Object.defineProperty(claimDigests, names[i], {value: b64Digest, enumerable: true});
    }
    return {data: data, digests: claimDigests};
}