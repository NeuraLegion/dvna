var express = require('express')
var path = require('path')
var favicon = require('serve-favicon')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var expressValidator = require('express-validator')
var flash = require('connect-flash')
var session = require('express-session')
var passport = require('passport')
var redis = require('redis')
var RedisStore = require('connect-redis')(session)
var sassMiddleware = require('node-sass-middleware')

var app = express()
var redisClient = redis.createClient(process.env.REDIS_URL)

require('./config/passport')(passport)
var routes = require('./routes/main')(passport)

var isProduction = process.env.NODE_ENV === 'production'

app.set('trust proxy', 1)

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use(favicon(path.join(__dirname, 'public', 'images', 'favicon.ico')))
app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(expressValidator())
app.use(flash())
app.use(session({
	secret: 'change-this-secret',
	resave: false,
	saveUninitialized: false,
	proxy: true,
	cookie: {
		secure: true,
		httpOnly: true,
		sameSite: 'lax'
	}
}))
app.use(passport.initialize())
app.use(passport.session())

app.use(sassMiddleware({
	src: path.join(__dirname, 'public'),
	dest: path.join(__dirname, 'public'),
	indentedSyntax: false,
	sourceMap: isProduction ? false : true
}))

app.use(express.static(path.join(__dirname, 'public')))
app.use('/', routes)

app.use(function (req, res, next) {
	var err = new Error('Not Found')
	err.status = 404
	next(err)
})

if (!isProduction) {
	app.use(function (err, req, res, next) {
		res.status(err.status || 500)
		res.render('error', {
			message: err.message,
			error: err
		})
	})
} else {
	app.use(function (err, req, res, next) {
		res.status(err.status || 500)
		res.render('error', {
			message: err.message,
			error: {}
		})
	})
}

module.exports = app
