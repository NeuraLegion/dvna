var express = require('express')
var path = require('path')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var session = require('express-session')
var passport = require('passport')
var flash = require('connect-flash')
var helmet = require('helmet')
var MongoStore = require('connect-mongo')(session)
var app = express()

// Security headers
app.use(helmet())
app.use(helmet.contentSecurityPolicy({
	directives: {
		defaultSrc: ["'self'"],
		scriptSrc: ["'self'", "https://maxcdn.bootstrapcdn.com", "https://cdnjs.cloudflare.com"],
		styleSrc: ["'self'", "https://maxcdn.bootstrapcdn.com"],
		imgSrc: ["'self'", 'data:'],
		fontSrc: ["'self'", "https://maxcdn.bootstrapcdn.com", "https://cdnjs.cloudflare.com"],
		objectSrc: ["'none'"],
		baseUri: ["'self'"],
		frameAncestors: ["'self'"]
	}
}))
app.use(helmet.hsts({
	maxAge: 15552000,
	includeSubDomains: true
}))

app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))

app.use(session({
	secret: process.env.SESSION_SECRET || 'change-me-in-production',
	resave: false,
	saveUninitialized: false,
	cookie: {
		httpOnly: true,
		secure: process.env.NODE_ENV === 'production',
		sameSite: 'lax'
	},
	store: new MongoStore({
		url: process.env.MONGODB_URI
	})
}))

app.use(flash())
app.use(passport.initialize())
app.use(passport.session())

module.exports = app
