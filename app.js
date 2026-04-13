var express = require('express')
var session = require('express-session')
var serverConfig = require('./config/server')

var app = express()

app.use(session({
	secret: serverConfig.sessionSecret,
	resave: false,
	saveUninitialized: false,
	cookie: {
		secure: serverConfig.cookieSecure
	}
}))

module.exports = app
