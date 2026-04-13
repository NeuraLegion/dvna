var path = require('path')
var express = require('express')
var cookieParser = require('cookie-parser')
var logger = require('morgan')
var session = require('express-session')
var helmet = require('helmet')
var hpp = require('hpp')
var flash = require('connect-flash')
var lusca = require('lusca')
var config = require('./config/server')

var app = express()

app.disable('x-powered-by')
app.set('trust proxy', 1)
app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use(logger('dev'))
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(session({
	secret: config.sessionSecret,
	resave: false,
	saveUninitialized: false,
	cookie: {
		httpOnly: true,
		secure: config.secureCookies,
		sameSite: 'lax'
	}
}))
app.use(flash())
app.use(hpp())
app.use(helmet({
	contentSecurityPolicy: {
		useDefaults: true,
		directives: {
			defaultSrc: ["'self'"],
			scriptSrc: ["'self'", 'https://maxcdn.bootstrapcdn.com', 'https://cdnjs.cloudflare.com'],
			styleSrc: ["'self'", "'unsafe-inline'", 'https://maxcdn.bootstrapcdn.com'],
			imgSrc: ["'self'", 'data:'],
			fontSrc: ["'self'", 'https://maxcdn.bootstrapcdn.com', 'data:'],
			objectSrc: ["'none'"],
			baseUri: ["'self'"],
			frameAncestors: ["'self'"]
		}
	},
	frameguard: { action: 'sameorigin' },
	xssFilter: false,
	hsts: {
		maxAge: 31536000,
		includeSubDomains: true
	}
}))
app.use(lusca.csrf())
app.use(express.static(path.join(__dirname, 'public')))

app.use('/', require('./routes/index')())
app.use('/app', require('./routes/app')())
app.use('/api', require('./routes/api')())

module.exports = app
