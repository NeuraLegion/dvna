var express = require('express')
var path = require('path')
var favicon = require('serve-favicon')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var session = require('express-session')
var flash = require('connect-flash')
var passport = require('passport')
var SequelizeStore = require('connect-session-sequelize')(session.Store)
var db = require('./models')
var routes = require('./routes/index')
var serverConfig = require('./config/server')

var app = express()

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use(favicon(path.join(__dirname, 'public', 'images', 'favicon.ico')))
app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())

app.use(function (req, res, next) {
	res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
	res.setHeader('X-Content-Type-Options', 'nosniff')
	res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; img-src 'self' data:; font-src 'self' https://maxcdn.bootstrapcdn.com")

	if (serverConfig.corsOrigin) {
		res.setHeader('Vary', 'Origin')
		res.setHeader('Access-Control-Allow-Origin', serverConfig.corsOrigin)
		res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
		res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization')
	}

	if (req.method === 'OPTIONS') {
		return res.sendStatus(204)
	}

	next()
})

app.use(express.static(path.join(__dirname, 'public')))

var store = new SequelizeStore({
	db: db.sequelize
})

app.use(session({
	secret: serverConfig.sessionSecret,
	resave: false,
	saveUninitialized: false,
	store: store,
	cookie: {
		httpOnly: true,
		secure: true,
		sameSite: 'lax'
	}
}))

store.sync()

app.use(passport.initialize())
app.use(passport.session())
app.use(flash())

app.use('/', routes(passport))

module.exports = app
