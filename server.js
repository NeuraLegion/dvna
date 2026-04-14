var express = require('express')
var path = require('path')
var cookieParser = require('cookie-parser')
var logger = require('morgan')
var session = require('express-session')
var flash = require('connect-flash')
var passport = require('./config/passport')
var routes = require('./routes/main')
var appConfig = require('./config/server')

var app = express()

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

// Trust reverse proxy headers so req.secure and secure cookies work correctly
// when the app is deployed behind a TLS-terminating proxy/load balancer.
app.set('trust proxy', appConfig.session.proxy ? 1 : false)

app.use(logger('dev'))
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))

function isSecureRequest(req) {
	return req.secure || req.headers['x-forwarded-proto'] === 'https'
}

app.use(session({
	secret: appConfig.session.secret,
	resave: appConfig.session.resave,
	saveUninitialized: appConfig.session.saveUninitialized,
	proxy: appConfig.session.proxy,
	cookie: {
		httpOnly: appConfig.session.cookie.httpOnly,
		secure: appConfig.session.cookie.secure ? 'auto' : false,
		sameSite: appConfig.session.cookie.sameSite,
		path: '/'
	}
}))

// Ensure any manually cleared session cookie matches the actual transport
// security of the current request so the browser accepts the deletion.
app.use(function (req, res, next) {
	var originalClearCookie = res.clearCookie.bind(res)

	res.clearCookie = function (name, options) {
		var cookieOptions = Object.assign({
			path: '/',
			httpOnly: true,
			sameSite: 'lax'
		}, options || {})

		if (name === 'connect.sid') {
			cookieOptions.secure = isSecureRequest(req)
		}

		return originalClearCookie(name, cookieOptions)
	}

	next()
})

app.use(flash())
app.use(passport.initialize())
app.use(passport.session())
app.use('/', routes(passport))

module.exports = app
