var express = require('express')
var app = express()
var session = require('express-session')
var serverConfig = require('./config/server')

app.set('trust proxy', 1)

app.use(session(serverConfig.session))

module.exports = app
