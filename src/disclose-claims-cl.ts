// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { Option, Command } from 'commander';
import { discloseClaimsFiles } from './disclose-claims';

const DEFAULT_QR_PATH = "qr.png";

interface Options {
    qrPath: string;
    type: string;
    claims: string[];
    outQrPath: string;
}

// process options
const program = new Command();
program.requiredOption('-q, --qrPath <qrPath>', 'path to the input QR code text or image to modify');
program.addOption(new Option('-t, --type <type>', 'type of the QR code').choices(['image', 'text']).default('image'));
program.requiredOption('-c, --claims <claims...>', 'name of claims to disclosed');
program.option('-o, --outQrPath <outQrPath>', 'path to the output QR', DEFAULT_QR_PATH);
program.parse(process.argv);
const options = program.opts() as Options;

void (async () => {
    try {
        await discloseClaimsFiles(options.type, options.qrPath, options.claims, options.outQrPath);
    } catch (err) {
        console.log(err);
    }
})();