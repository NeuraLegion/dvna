var express = require('express')
var session = require('express-session')
var appConfig = require('./config/server')
var app = express()

if (appConfig.session && appConfig.session.proxy) {
	app.set('trust proxy', 1)
}

app.use(session({
	secret: appConfig.session.secret,
	resave: appConfig.session.resave,
	saveUninitialized: appConfig.session.saveUninitialized,
	proxy: appConfig.session.proxy,
	cookie: {
		httpOnly: appConfig.session.cookie.httpOnly,
		secure: process.env.NODE_ENV === 'production' ? true : 'auto',
		sameSite: appConfig.session.cookie.sameSite,
		path: appConfig.session.cookie.path
	}
}))

module.exports = app
