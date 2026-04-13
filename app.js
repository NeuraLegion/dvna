var express = require('express')
var app = express()
var appRouter = require('./routes/app')

app.disable('x-powered-by')

app.use(function (req, res, next) {
	res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	next()
})

app.use('/app', appRouter())

module.exports = app
