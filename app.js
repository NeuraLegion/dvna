var express = require('express')
var session = require('express-session')
var path = require('path')

var app = express()

function isSecureRequest(req) {
	return req.secure || req.headers['x-forwarded-proto'] === 'https'
}

// Trust proxy when deployed behind a TLS-terminating reverse proxy so req.secure works correctly.
// This allows express-session to apply Secure cookies appropriately in production HTTPS deployments.
if (process.env.TRUST_PROXY === 'true' || process.env.NODE_ENV === 'production') {
	app.set('trust proxy', 1)
}

app.use(session({
	secret: process.env.SESSION_SECRET || 'change-me',
	resave: false,
	saveUninitialized: false,
	proxy: true,
	cookie: {
		httpOnly: true,
		sameSite: 'lax',
		secure: isSecureRequest({
			secure: process.env.NODE_ENV === 'production',
			headers: {
				'x-forwarded-proto': process.env.X_FORWARDED_PROTO || 'https'
			}
		})
	}
}))

app.use(express.static(path.join(__dirname, 'public')))

app.use('/', require('./routes/main')())
app.use('/app', require('./routes/app')())

module.exports = app
