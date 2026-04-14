var express = require('express')
var session = require('express-session')
var passport = require('passport')

var app = express()

app.set('trust proxy', 1)

app.use(session({
  secret: 'keyboard cat',
  resave: true,
  saveUninitialized: true,
  cookie: { secure: process.env.NODE_ENV === 'production' }
}))

app.use(passport.initialize())
app.use(passport.session())

module.exports = app
