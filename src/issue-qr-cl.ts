// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { Command } from 'commander';
import { issueQrFiles } from './issue-qr';

interface Options {
    privateKeyPath: string;
    jwtPath: string;
    claimValuesPath: string;
    outQrPath: string;
}
const DEFAULT_QR_PATH = "qr.png";

// process options
const program = new Command();
program.requiredOption('-k, --privateKeyPath <privateKeyPath>', 'path to the issuer signing secret key file');
program.requiredOption('-t, --jwtPath <jwtPath>', 'path to the JWT to encode into a QR');
program.option('-c, --claimValuesPath <claimValuesPath>', 'path to the input claim values object');
program.option('-o, --outQrPath <outQrPath>', 'path to the output QR code');
program.parse(process.argv);
const options = program.opts() as Options;
if (!options.outQrPath) {
    options.outQrPath = DEFAULT_QR_PATH;
}

void (async () => {
    try {
        await issueQrFiles(options.privateKeyPath, options.jwtPath, options.outQrPath, options.claimValuesPath);
    } catch (err) {
        console.log(err);
    }
})();