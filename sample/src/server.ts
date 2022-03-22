import { verify } from 'crypto';
import express from 'express';
import http from 'http';
import {issueQrAsDataUrl} from '../../src/issue-qr';
import {verifyQr} from '../../src/verify-qr';

const app = express();
app.use(express.json()) // for parsing application/json
app.use(express.static('./public')) // public files

interface IssueQrParams {
    jwt: any,
    private: any
}

app.post('/issue-qr', async (req, res) => {
    console.log('Received POST for', '/issue-qr', req.body);
    res.type('json');
    try {
        const params = req.body as IssueQrParams;
        const result = await issueQrAsDataUrl(params.private, params.jwt);
        const response = {qr: result};
        console.log(response);
        res.send(response);
    } catch (err) {
        const errString = err as string;
        console.log("Error: " + errString);
        res.send({error: errString});
    }
});

interface VerifyQrParams {
    qr: string,
    jwks?: any
}

app.post('/verify-qr', async (req, res) => {
    console.log('Received POST for', '/verify-qr', req.body);
    res.type('json');
    try {
        const params = req.body as VerifyQrParams;
        const result = await verifyQr(params.qr, params.jwks);
        const response = {jwt: result};
        console.log(response);
        res.send(response);
    } catch (err) {
        const errString = err as string;
        console.log("Error: " + errString);
        res.send({error: errString});
    }
});

http.createServer(app).listen(8080, () => {
    const url = 'http://localhost:8080/';
    console.log("Service listening at " + url);
    console.log("Issuer portal:  " + url + 'issuer.html');
    console.log("Verifier portal:  " + url + 'verifier.html');
});
