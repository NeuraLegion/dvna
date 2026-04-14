var express = require('express')
var app = express()
var path = require('path')
var bodyParser = require('body-parser')
var cookieParser = require('cookie-parser')
var session = require('express-session')
var flash = require('connect-flash')
var passport = require('passport')
var fileUpload = require('express-fileupload')

var appRoutes = require('./routes/app')
var authRoutes = require('./routes/auth')
var learnRoutes = require('./routes/learn')

var trustedOrigins = [
	'http://localhost:3000',
	'http://127.0.0.1:3000'
]

function corsMiddleware (req, res, next) {
	var origin = req.headers.origin
	if (origin && trustedOrigins.indexOf(origin) !== -1) {
		res.setHeader('Access-Control-Allow-Origin', origin)
		res.setHeader('Access-Control-Allow-Credentials', 'true')
		res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
		res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
		res.setHeader('Access-Control-Max-Age', '600')
		res.setHeader('Vary', 'Origin')
	}

	if (req.method === 'OPTIONS') {
		return res.sendStatus(204)
	}

	next()
}

app.use(corsMiddleware)

app.use(function (req, res, next) {
	res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	if (!res.getHeader('Strict-Transport-Security') && (req.secure || req.headers['x-forwarded-proto'] === 'https')) {
		res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
	}
	res.setHeader('X-Content-Type-Options', 'nosniff')
	res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
	next()
})

app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())
app.use(cookieParser())
app.use(session({
	secret: 'change-this-secret',
	resave: false,
	saveUninitialized: false
}))
app.use(flash())
app.use(passport.initialize())
app.use(passport.session())
app.use(fileUpload())

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use('/app', appRoutes())
app.use('/auth', authRoutes())
app.use('/learn', learnRoutes())

module.exports = app
