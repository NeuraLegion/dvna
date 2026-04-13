var express = require('express')
var path = require('path')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var session = require('express-session')
var MongoStore = require('connect-mongo')(session)
var appConfig = require('./config/app')
var serverConfig = require('./config/server')
var routes = require('./routes')

var app = express()

// Trust proxy headers so secure cookies work correctly when HTTPS is terminated
// at a load balancer / reverse proxy.
if (serverConfig.cookieSecure) {
	app.set('trust proxy', 1)
}

app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(session({
	secret: appConfig.sessionSecret,
	resave: false,
	saveUninitialized: false,
	cookie: {
		secure: serverConfig.cookieSecure,
		httpOnly: true
	},
	store: new MongoStore({
		url: serverConfig.mongoUrl,
		collection: 'sessions'
	})
}))

app.use('/', routes())

module.exports = app
