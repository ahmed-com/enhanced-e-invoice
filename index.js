const express = require('express');
const bodyParser = require('body-parser');
const Signer = require('./Signer');

const app = express();

app.use(bodyParser.json());

app.use((req, res, next) => {
	res.setHeader('Access-Control-Allow-Origin', '*');
	res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
	res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
	next();
});

app.post('/sign', (req, res, next) => {
	const pin = req.body.pin;
    const id = req.body.id;
	const document = req.body.document;
	const jsonStr = JSON.stringify(document);
	let signature;
	try {
		const signer = new Signer(id,pin);
		signature = signer.signFile(jsonStr);
	} catch (err) {
		res.status(403).json({ message: 'unauthorized' });
		return;
	}

	res.status(200).json({ signature });
});

app.listen(4999, () => {
	console.log('running on port 4999');
});