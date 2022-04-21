This folder contains files to generate the spec examples. Make sure the `issue-qr.ts`'s `VERBOSE_OUTPUT` variable is set to `true`.

# Generate the normal example

```
npm run issue-qr -- -k examples/example.private.json -t examples/example.jwt.json -o img/example_qr.png
```

# Generate the selective disclosure example

```
npm run issue-qr -- -k examples/example.private.json -t examples/example.seldisc.jwt.json -c examples/example.seldisc.claims.json -o img/example_selectivedisclosure_qr.png
```