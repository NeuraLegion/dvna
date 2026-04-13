var express = require('express')
var app = express()
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var path = require('path')
var session = require('express-session')
var flash = require('connect-flash')
var passport = require('passport')
var helmet = require('helmet')

// Security headers
app.use(helmet({
	contentSecurityPolicy: false
}))

app.use(function (req, res, next) {
	res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; img-src 'self' data:; font-src 'self' https://maxcdn.bootstrapcdn.com")
	next()
})

// view engine setup
app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))

app.use(session({
	secret: 'keyboard cat',
	resave: false,
	saveUninitialized: false
}))
app.use(flash())
app.use(passport.initialize())
app.use(passport.session())

require('./config/passport')(passport)

app.use('/', require('./routes/main')(passport))

// catch 404 and forward to error handler
app.use(function (req, res, next) {
	var err = new Error('Not Found')
	err.status = 404
	next(err)
})

// error handlers
app.use(function (err, req, res, next) {
	res.locals.message = err.message
	res.locals.error = req.app.get('env') === 'development' ? err : {}

	res.status(err.status || 500)
	res.render('error')
})

module.exports = app
