var express = require('express')
var path = require('path')
var cookieParser = require('cookie-parser')
var logger = require('morgan')
var session = require('express-session')

var app = express()

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

// Trust the first proxy so secure cookies work correctly when the app is
// deployed behind a load balancer / reverse proxy terminating TLS.
app.set('trust proxy', 1)

app.use(logger('dev'))
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(cookieParser())

app.use(session({
	secret: process.env.SESSION_SECRET || 'change-me-in-production',
	resave: false,
	saveUninitialized: false,
	proxy: true,
	cookie: {
		httpOnly: true,
		secure: process.env.NODE_ENV === 'production',
		sameSite: 'lax',
		path: '/'
	}
}))

module.exports = app
