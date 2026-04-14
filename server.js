var express = require('express')
var path = require('path')
var favicon = require('serve-favicon')
var logger = require('morgan')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var session = require('express-session')
var passport = require('passport')
var flash = require('connect-flash')

var routes = require('./routes/index')
var appRoutes = require('./routes/app')

var app = express()

if (app.get('env') === 'production') {
    app.set('trust proxy', 1)
}

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')))
app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))

app.use(session({
  secret: 'keyboard cat',
  resave: true,
  saveUninitialized: true,
  cookie: { secure: app.get('env') === 'production' }
}))
app.use(passport.initialize())
app.use(passport.session())
app.use(flash())

app.use('/', routes())
app.use('/app', appRoutes())

module.exports = app
