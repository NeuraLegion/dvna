var express = require('express')
var path = require('path')
var favicon = require('serve-favicon')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var flash = require('connect-flash')
var expressSession = require('express-session')
var passport = require('passport')
var app = express()

require('./core/passport')(passport)
var routes = require('./routes/main')(passport)

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

// Required so secure cookies work correctly when the app is deployed behind a proxy
// that terminates TLS (e.g. Heroku, nginx, load balancers).
app.set('trust proxy', 1)

app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')))
app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))

app.use(expressSession({
	secret: process.env.SESSION_SECRET || 'your secret here',
	resave: false,
	saveUninitialized: false,
	proxy: true,
	cookie: {
		httpOnly: true,
		secure: true,
		sameSite: 'lax'
	}
}))

app.use(flash())
app.use(passport.initialize())
app.use(passport.session())

app.use('/', routes)

module.exports = app
