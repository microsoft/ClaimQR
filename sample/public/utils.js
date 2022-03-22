// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//
// Calls the Rest API on the server.
// Caller will specify when return type is other than JSON
//
async function restCall(url, data, method = 'POST', responseType = 'json') {

    const xhr = new XMLHttpRequest();

    return new Promise(function (resolve, reject) {

        xhr.open(method, url);

        if (data instanceof Object) {
            xhr.setRequestHeader("Content-Type", "application/json");
            data = JSON.stringify(data);
        }
        else if (typeof data === 'string') {
            xhr.setRequestHeader("Content-Type", "text/plain");
        }

        xhr.responseType = responseType;

        xhr.onreadystatechange = function () {
            if (xhr.readyState === 4) {
                resolve(xhr.response);
            }
        };

        xhr.onerror = function (err) {
            reject(err);
        }

        method === 'POST' ? xhr.send(data) : xhr.send();

    });
}

//
// Converts data om an ArrayBuffer to a base64-url encoded string
//
function arrayBufferToBase64url(arrayBuffer) {
    return toBase64Url(btoa(String.fromCharCode(...new Uint8Array(arrayBuffer))));
}


//
// Converts regular base64 to base64-url
//
function toBase64Url(base64Text) {
    return base64Text.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}


//
// Decode Base64Url
//
function decodeBase64Url(base64Encoded) {

    var b64 = base64Encoded.replace(/\-/g, '+').replace(/\_/g, '/');

    // pad to make valid Base64
    if (b64.length % 4 === 1) b64 += 'A';
    while (b64.length % 4 !== 0) {
        b64 += '='
    }

    const decoded = atob(b64)

    return decoded;
}


//
// Tries to parse JSON returning undefined if it fails
//
function tryParse(text) {
    try {
        return JSON.parse(text);
    } catch {
        return undefined;
    }
}

