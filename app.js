var express = require('express')
var path = require('path')
var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')
var flash = require('connect-flash')
var session = require('express-session')
var passport = require('passport')

var index = require('./routes/index')
var appRoutes = require('./routes/app')
var loginRoutes = require('./routes/login')
var apiRoutes = require('./routes/api')

var app = express()

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))

// Apply core security headers globally so all routes and render paths inherit them.
app.use(function (req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff')
  next()
})

app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: false
}))
app.use(flash())
app.use(passport.initialize())
app.use(passport.session())

app.use('/', index())
app.use('/app', appRoutes())
app.use('/login', loginRoutes())
app.use('/api', apiRoutes())

module.exports = app
