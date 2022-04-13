import express from 'express';
import http from 'http';
import rateLimit from 'express-rate-limit';
import {issueQrAsDataUrl} from '../../src/issue-qr';
import {verifyQr} from '../../src/verify-qr';
import {discloseClaimsAsDataUrl} from '../../src/disclose-claims';

const app = express();
app.use(express.json()) // for parsing application/json
app.use(express.static('./public')) // public files

// apply a rate limiter to incoming request (as suggested by CodeQL)
const limiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: 100, // Limit each IP to 100 requests per `window` (here, per 15 minutes)
	standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
	legacyHeaders: false, // Disable the `X-RateLimit-*` headers
})
app.use(limiter)

interface IssueQrParams {
    jwt: any,
    private: any,
    claimValues?: any
}

app.post('/issue-qr', async (req, res) => {
    console.log('Received POST for', '/issue-qr', req.body);
    res.type('json');
    try {
        const params = req.body as IssueQrParams;
        const result = await issueQrAsDataUrl(params.private, params.jwt, params.claimValues);
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

interface DiscloseClaimsParams {
    qr: string,
    claims: string[]
}

app.post('/disclose-claims', async (req, res) => {
    console.log('Received POST for', '/disclose-claims', req.body);
    res.type('json');
    try {
        const params = req.body as DiscloseClaimsParams;
        const result = await discloseClaimsAsDataUrl(params.qr, params.claims);
        const response = {qr: result};
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
    console.log("Holder portal:  " + url + 'holder.html');
    console.log("Verifier portal:  " + url + 'verifier.html');
});
