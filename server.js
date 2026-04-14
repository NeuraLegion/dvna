var express = require('express')
var session = require('express-session')

var app = express()

// If the app is behind a reverse proxy / load balancer, this allows Express
// to correctly detect HTTPS via X-Forwarded-Proto when deciding whether to
// send secure cookies.
app.set('trust proxy', 1)

app.use(session({
	secret: 'change-this-secret',
	resave: false,
	saveUninitialized: false,
	cookie: {
		secure: process.env.NODE_ENV === 'production',
		httpOnly: true,
		sameSite: 'lax'
	}
}))

module.exports = app
