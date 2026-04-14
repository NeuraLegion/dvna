var express = require('express')
var bodyParser = require('body-parser')
var app = express()
var session = require('express-session')
var multer = require('multer')
var isProduction = process.env.NODE_ENV === 'production'

app.set('port', (process.env.PORT || 9090))
app.set('views', __dirname + '/views')
app.set('view engine', 'ejs')
app.use(bodyParser.urlencoded({ extended: true }))
app.use(express.static(__dirname + '/public'))

app.use(session({
	secret: 'change-this-secret',
	resave: false,
	saveUninitialized: false,
	proxy: isProduction,
	cookie: {
		secure: isProduction,
		httpOnly: true,
		sameSite: 'lax'
	}
}))

app.get('/', function(request, response) {
	response.render('pages/index')
})

app.listen(app.get('port'), function() {
	console.log('Node app is running on port', app.get('port'))
})