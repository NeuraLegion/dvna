var express = require('express')
var app = express()
var mainRouter = require('./routes/app')

app.use(function (req, res, next) {
	res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	res.setHeader('Content-Security-Policy', "default-src 'self'; frame-ancestors 'self'")
	next()
})

app.use('/', mainRouter())

module.exports = app
