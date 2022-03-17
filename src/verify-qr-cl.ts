// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { Option, Command } from 'commander';
import { verifyQrFiles } from './verify-qr';

interface Options {
    qrPath: string;
    type: string;
    jwtPath: string;
    jwksPath: string;
}
const DEFAULT_JWT_PATH = "jwt.json";

// process options
const program = new Command();
program.requiredOption('-p, --qrPath <qrPath>', 'path to the input QR code text or image');
program.addOption(new Option('-t, --type <type>', 'type of the QR code').choices(['image', 'text']).default('image'));
program.option('-k, --jwksPath <jwksPath>', "optional path to the JWKS file containing public key, for offline validation");
program.option('-j, --jwtPath <jwtPath>', 'path to the output JWT', DEFAULT_JWT_PATH);
program.parse(process.argv);
const options = program.opts() as Options;

void (async () => {
    try {
        await verifyQrFiles(options.type, options.qrPath, options.jwtPath, options.jwksPath)
    } catch (err) {
        console.log(err);
    }
})();