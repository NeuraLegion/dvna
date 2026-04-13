var express = require('express')
var path = require('path')
var cookieParser = require('cookie-parser')
var logger = require('morgan')
var session = require('express-session')
var MongoStore = require('connect-mongo')

var appConfig = require('./config/app')
var serverConfig = require('./config/server')

var app = express()

function toBoolean(value) {
	return value === true || value === 'true' || value === '1'
}

function isHttpsRequest(req) {
	if (!req) {
		return false
	}

	return req.secure || req.headers['x-forwarded-proto'] === 'https'
}

function shouldUseSecureCookie(req) {
	if (toBoolean(process.env.COOKIE_SECURE)) {
		return true
	}

	if (process.env.NODE_ENV === 'production') {
		return true
	}

	return isHttpsRequest(req)
}

// Trust reverse proxies so req.secure works correctly when TLS is terminated upstream.
app.set('trust proxy', 1)

app.use(logger('dev'))
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))

app.use(function (req, res, next) {
	var secureCookie = shouldUseSecureCookie(req)

	app.use(session({
		secret: appConfig.sessionSecret,
		resave: false,
		saveUninitialized: false,
		proxy: true,
		cookie: {
			secure: secureCookie,
			httpOnly: true,
			sameSite: 'lax'
		},
		store: new MongoStore({
			url: serverConfig.mongoUrl,
			collection: 'sessions'
		})
	}))

	return next()
})

module.exports = app
