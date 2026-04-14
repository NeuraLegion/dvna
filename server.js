var express = require('express')
var app = express()
var session = require('express-session')

app.set('trust proxy', 1)

app.use(session({
  secret: 'keyboard cat',
  resave: true,
  saveUninitialized: true,
  cookie: { secure: true }
}))
