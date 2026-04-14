var express = require('express')
var path = require('path')
var favicon = require('serve-favicon')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var flash = require('connect-flash')
var session = require('express-session')
var passport = require('passport')
var expressValidator = require('express-validator')

var app = express()

app.set('trust proxy', 1)

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')))
app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(expressValidator())
app.use(express.static(path.join(__dirname, 'public')))
app.use(session({
	secret: process.env.SESSION_SECRET || 'dev-secret',
	resave: false,
	saveUninitialized: false,
	cookie: {
		httpOnly: true,
		secure: true,
		sameSite: 'lax'
	}
}))
app.use(flash())
app.use(passport.initialize())
app.use(passport.session())

require('./config/passport')(passport)

app.use('/', require('./routes/main')(passport))

app.use(function (req, res, next) {
	var err = new Error('Not Found')
	err.status = 404
	next(err)
})

app.use(function (err, req, res, next) {
	res.status(err.status || 500)
	res.render('error', {
		message: err.message,
		error: req.app.get('env') === 'development' ? err : {}
	})
})

module.exports = app
