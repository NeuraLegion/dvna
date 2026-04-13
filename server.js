var express = require('express')
var session = require('express-session')

var app = express()

app.set('trust proxy', 1)

app.use(function (req, res, next) {
    if (req.secure) {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    }
    next()
})

// existing middleware and routes continue below
