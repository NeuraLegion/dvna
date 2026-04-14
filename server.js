var express = require('express')
var path = require('path')
var app = express()
var helmet = require('helmet')
var cors = require('cors')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var session = require('express-session')
var flash = require('connect-flash')
var passport = require('passport')

var mainRouter = require('./routes/main')

var trustedOrigins = (process.env.CORS_ALLOWED_ORIGINS || '').split(',').map(function (origin) {
	return origin.trim()
}).filter(function (origin) {
	return origin.length > 0
})

app.set('view engine', 'ejs')
app.set('views', path.join(__dirname, 'views'))

app.use(helmet.noSniff())

app.use(cors({
	origin: function (origin, callback) {
		if (!origin) {
			return callback(null, false)
		}

		if (trustedOrigins.indexOf(origin) !== -1) {
			return callback(null, origin)
		}

		return callback(new Error('Not allowed by CORS'))
	},
	credentials: true
}))

app.use(function (req, res, next) {
	res.setHeader('X-Content-Type-Options', 'nosniff')
	next()
})

app.use(cookieParser())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())
app.use(session({
	secret: process.env.SESSION_SECRET || 'dvnasecret',
	resave: false,
	saveUninitialized: false,
	cookie: {
		httpOnly: true,
		secure: false,
		sameSite: 'lax'
	}
}))
app.use(flash())
app.use(passport.initialize())
app.use(passport.session())

app.use('/', mainRouter(passport))

module.exports = app
