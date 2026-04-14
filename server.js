var express = require('express')
var path = require('path')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var session = require('express-session')
var passport = require('passport')
var flash = require('connect-flash')

var isProduction = process.env.NODE_ENV === 'production'

var app = express()

if (isProduction) {
	app.set('trust proxy', 1)
}

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(session({
	secret: 'change-this-secret',
	resave: false,
	saveUninitialized: false,
	proxy: isProduction,
	cookie: {
		secure: isProduction,
		httpOnly: true,
		sameSite: 'lax'
	}
}))
app.use(passport.initialize())
app.use(passport.session())
app.use(flash())

app.use(express.static(path.join(__dirname, 'public')))

module.exports = app
