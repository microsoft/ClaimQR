// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { Command } from 'commander';
import { issueQrFiles } from './issue-qr';

interface Options {
    privatePath: string;
    jwtPath: string;
    qrPath: string;
}
const DEFAULT_QR_PATH = "qr.png";

// process options
const program = new Command();
program.requiredOption('-p, --privatePath <privatePath>', 'path to the issuer signing secret key file');
program.requiredOption('-t, --jwtPath <jwtPath>', 'path to the JWT to encode into a QR');
program.option('-q, --qrPath <qrPath>', 'path to the output QR code');
program.parse(process.argv);
const options = program.opts() as Options;
if (!options.qrPath) {
    options.qrPath = DEFAULT_QR_PATH;
}

void (async () => {
    try {
        await issueQrFiles(options.privatePath, options.jwtPath, options.qrPath);
    } catch (err) {
        console.log(err);
    }
})();