var express = require('express')
var bodyParser = require('body-parser')
var passport = require('passport')
var session = require('express-session')
var csrf = require('csurf')
var ejs = require('ejs')
var morgan = require('morgan')
const fileUpload = require('express-fileupload');
var config = require('./config/server')

//Initialize Express
var app = express()
require('./core/passport')(passport)
app.use(express.static('public'))
app.set('view engine','ejs')
app.use(morgan('tiny'))
app.use(bodyParser.urlencoded({ extended: false }))
app.use(fileUpload());

// Enable for Reverse proxy support
// app.set('trust proxy', 1) 

// Intialize Session
app.use(session({
  secret: 'keyboard cat',
  resave: true,
  saveUninitialized: true,
  cookie: { secure: false, sameSite: 'strict', httpOnly: true }
}))

// Disable automatic OPTIONS handling and reject the method consistently
app.options('*', function (req, res) {
  res.set('Allow', 'GET, POST')
  return res.status(405).send('Method Not Allowed')
})
app.use(function (req, res, next) {
  if (req.method === 'OPTIONS') {
    res.set('Allow', 'GET, POST')
    return res.status(405).send('Method Not Allowed')
  }
  next()
})

// Initialize Passport
app.use(passport.initialize())
app.use(passport.session())

// CSRF protection: preserve GET so login/register/reset pages can render,
// and protect state-changing methods.
var csrfProtection = csrf()
app.use(function (req, res, next) {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    return csrfProtection(req, res, next)
  }
  next()
})
app.use(function (req, res, next) {
  if (req.session) {
    if (!req.session.csrfFormToken && req.csrfToken) {
      req.session.csrfFormToken = req.csrfToken()
    }
    res.locals.csrfToken = req.session.csrfFormToken
  }
  next()
})

// Initialize express-flash
app.use(require('express-flash')());

// Routing
app.use('/app',require('./routes/app')())
app.use('/',require('./routes/main')(passport))

// Start Server
app.listen(config.port, config.listen)
