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
