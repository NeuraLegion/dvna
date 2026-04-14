var express = require('express')
var path = require('path')
var app = express()
var config = require('./config/server')

// Security headers
app.use(function (req, res, next) {
    res.setHeader('X-Frame-Options', 'SAMEORIGIN')
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    next()
})

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')

module.exports = app

if (require.main === module) {
    app.listen(config.port, config.listen, function () {
        console.log('Server listening on ' + config.listen + ':' + config.port)
    })
}