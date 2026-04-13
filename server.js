var express = require('express')
var app = express()

app.use(function (req, res, next) {
	res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	next()
})

app.use(function (req, res, next) {
	if (req.method === 'OPTIONS') {
		return res.status(405).send('Method Not Allowed')
	}
	next()
})

module.exports = app
