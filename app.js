var express = require('express')
var session = require('express-session')
var serverConfig = require('./config/server')
var app = express()

app.use(function (req, res, next) {
	res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	next()
})

app.use(session(serverConfig.session))

module.exports = app