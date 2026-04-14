var express = require('express')
var session = require('express-session')
var serverConfig = require('./config/server')

var app = express()

if (serverConfig.session && serverConfig.session.proxy) {
	app.set('trust proxy', 1)
}

app.use(session(serverConfig.session))

module.exports = app
