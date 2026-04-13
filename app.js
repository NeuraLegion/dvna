var express = require('express')
var session = require('express-session')
var passport = require('passport')
var bodyParser = require('body-parser')
var flash = require('connect-flash')
var path = require('path')

var app = express()

// If the app is deployed behind a reverse proxy / TLS terminator, trust the proxy
// so req.secure is populated correctly and secure cookies can be set safely.
app.set('trust proxy', 1)

app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())
app.use(flash())

app.use(session({
	secret: process.env.SESSION_SECRET || 'change-me',
	resave: false,
	saveUninitialized: false,
	cookie: {
		httpOnly: true,
		sameSite: 'lax',
		secure: true
	}
}))

app.use(passport.initialize())
app.use(passport.session())

app.use(express.static(path.join(__dirname, 'public')))

module.exports = app
