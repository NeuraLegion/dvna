var db = require('../models')
var bCrypt = require('bcrypt')
const execFile = require('child_process').execFile;
var mathjs = require('mathjs')
var libxmljs = require("libxmljs");
var serialize = require("node-serialize")
const Op = db.Sequelize.Op

var allowedOrigins = (process.env.CORS_ORIGINS || '').split(',').map(function (origin) {
	return origin.trim()
}).filter(Boolean)

function getAllowedOrigin(req) {
	var requestOrigin = req && req.headers ? req.headers.origin : null
	if (requestOrigin && allowedOrigins.indexOf(requestOrigin) !== -1) {
		return requestOrigin
	}
	return null
}

function applyCorsHeaders(req, res) {
	var allowedOrigin = getAllowedOrigin(req)
	if (!allowedOrigin) {
		return false
	}

	if (!res.getHeader('Access-Control-Allow-Origin')) {
		res.setHeader('Access-Control-Allow-Origin', allowedOrigin)
	}

	if (!res.getHeader('Vary')) {
		res.setHeader('Vary', 'Origin')
	} else if (String(res.getHeader('Vary')).indexOf('Origin') === -1) {
		res.setHeader('Vary', String(res.getHeader('Vary')) + ', Origin')
	}

	if (!res.getHeader('Access-Control-Allow-Credentials')) {
		res.setHeader('Access-Control-Allow-Credentials', 'true')
	}

	return true
}

function logDbError(context, err) {
	var message = err && err.message ? err.message : 'unknown error'
	console.error(context + ': ' + message)
	if (err && err.name) {
		console.error(context + ': ' + err.name)
	}
}

function applyClickjackingProtection(res) {
	res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	res.setHeader('Content-Security-Policy', "frame-ancestors 'self'")
	res.setHeader('X-Content-Type-Options', 'nosniff')
}

function applyResponseSecurityHeaders(res) {
	res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; img-src 'self' data:; font-src 'self' data: https://maxcdn.bootstrapcdn.com; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'")
	res.setHeader('X-Content-Type-Options', 'nosniff')
}

function applyPingSecurityHeaders(res) {
	res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; img-src 'self' data:; font-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'")
	res.setHeader('X-Content-Type-Options', 'nosniff')
}

function applyAppPageSecurityHeaders(res) {
	res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; img-src 'self' data:; font-src 'self' data: https://maxcdn.bootstrapcdn.com; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'")
	res.setHeader('X-Content-Type-Options', 'nosniff')
}

function renderModifyProductError(req, res, product) {
	applyClickjackingProtection(res)
	req.flash('danger', 'Unable to save product')
	res.render('app/modifyproduct', {
		output: {
			product: product
		}
	})
}

function handleModifyProductError(req, res, product, err) {
	logDbError('modifyProductSubmit failed', err)
	renderModifyProductError(req, res, product)
}

function isValidPingTarget(address) {
	if (typeof address !== 'string') {
		return false
	}

	address = address.trim()
	if (!address) {
		return false
	}

	// Allow IPv4, IPv6, and hostnames; avoid shell metacharacters entirely.
	var ipv4 = /^(?:25[0-5]|2-4\d|1?\d?\d)(?:\.(?:25[0-5]|2[4]\d|1?\d?\d)){3}$/
	var ipv6 = /^\[[0-9a-fA-F:]+\]$|^[0-9a-fA-F:]+$/
	var hostname = /^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)*(?!-)[A-Za-z0-9-]{1,63}(?<!-)$/

	return ipv4.test(address) || ipv6.test(address) || hostname.test(address)
}

module.exports.userSearch = function (req, res) {
	applyResponseSecurityHeaders(res)

	var query = "SELECT name,id FROM Users WHERE login='" + req.body.login + "'"
	db.sequelize.query(query, {
		model: db.User
	}).then(user => {
		if (user.length) {
			var output = {
				user: {
					name: user[0].name,
					id: user[0].id
				}
			}
			res.render('app/usersearch', {
				output: output
			})
		} else {
			req.flash('warning', 'User not found')
			res.render('app/usersearch', {
				output: null
			})
		}
	}).catch(err => {
		req.flash('danger', 'Internal Error')
		res.render('app/usersearch', {
			output: null
		})
	})
}

module.exports.ping = function (req, res) {
	applyPingSecurityHeaders(res)

	var address = req.body.address
	if (!isValidPingTarget(address)) {
		req.flash('warning', 'Invalid address')
		res.render('app/ping', {
			output: 'Invalid address'
		})
		return
	}

	address = address.trim()
	execFile('ping', ['-c', '2', address], function (err, stdout, stderr) {
		var output = stdout + stderr
		res.render('app/ping', {
			output: output
		})
	})
}

module.exports.listProducts = function (req, res) {
	applyCorsHeaders(req, res)
	applyClickjackingProtection(res)
	res.setHeader('X-Content-Type-Options', 'nosniff')

	db.Product.findAll().then(products => {
		output = {
			products: products
		}
		res.render('app/products', {
			output: output
		})
	})
}

module.exports.productSearch = function (req, res) {
	db.Product.findAll({
		where: {
			name: {
				[Op.like]: '%' + req.body.name + '%'
			}
		}
	}).then(products => {
		output = {
			products: products,
			searchTerm: req.body.name
		}
		res.render('app/products', {
			output: output
		})
	})
}

module.exports.modifyProduct = function (req, res) {
	applyClickjackingProtection(res)
	if (!req.query.id || req.query.id == '') {
		output = {
			product: {}
		}
		res.render('app/modifyproduct', {
			output: output
		})
	} else {
		db.Product.find({
			where: {
				'id': req.query.id
			}
		}).then(product => {
			if (!product) {
				product = {}
			}
			output = {
				product: product
			}
			res.render('app/modifyproduct', {
				output: output
			})
		}).catch(err => {
			logDbError('modifyProduct failed', err)
			req.flash('danger', 'Unable to load product')
			res.render('app/modifyproduct', {
				output: {
					product: {}
				}
			})
		})
	}
}

module.exports.modifyProductSubmit = function (req, res) {
	applyClickjackingProtection(res)
	if (!req.body.id || req.body.id == '') {
		req.body.id = 0
	}
	db.Product.find({
		where: {
			'id': req.body.id
		}
	}).then(product => {
		if (!product) {
			product = new db.Product()
		}
		product.code = req.body.code
		product.name = req.body.name
		product.description = req.body.description
		product.tags = req.body.tags
		product.save().then(p => {
			if (p) {
				req.flash('success', 'Product added/modified!')
				res.setHeader('X-Content-Type-Options', 'nosniff')
				res.redirect('/app/products')
			}
		}).catch(err => {
			handleModifyProductError(req, res, product, err)
		})
	}).catch(err => {
		logDbError('modifyProductSubmit lookup failed', err)
		renderModifyProductError(req, res, {
			id: req.body.id,
			code: req.body.code,
			name: req.body.name,
			description: req.body.description,
			tags: req.body.tags
		})
	})
}

module.exports.userEdit = function (req, res) {
	applyAppPageSecurityHeaders(res)
	res.render('app/useredit', {
		userId: req.user.id,
		userEmail: req.user.email,
		userName: req.user.name
	})
}

module.exports.userEditSubmit = function (req, res) {
	db.User.find({
		where: {
			'id': req.body.id
		} 		
	}).then(user =>{
		if(req.body.password.length>0){
			if(req.body.password.length>0){
				if (req.body.password == req.body.cpassword) {
					user.password = bCrypt.hashSync(req.body.password, bCrypt.genSaltSync(10), null)
				}else{
					req.flash('warning', 'Passwords dont match')
					res.render('app/useredit', {
						userId: req.user.id,
						userEmail: req.user.email,
						userName: req.user.name,
					})
					return		
				}
			}else{
				req.flash('warning', 'Invalid Password')
				res.render('app/useredit', {
					userId: req.user.id,
					userEmail: req.user.email,
					userName: req.user.name,
				})
				return
			}
		}
		user.email = req.body.email
		user.name = req.body.name
		user.save().then(function () {
			req.flash('success','Updated successfully')
			res.render('app/useredit', {
				userId: req.body.id,
				userEmail: req.body.email,
				userName: req.body.name,
			})
		})
	})
}

module.exports.redirect = function (req, res) {
	if (req.query.url) {
		res.redirect(req.query.url)
	} else {
		res.send('invalid redirect url')
	}
}

module.exports.calc = function (req, res) {
	// Security headers are applied by the /app router middleware so every calc
	// response path (including auth middleware/alternate flows) carries CSP.
	applyAppPageSecurityHeaders(res)
	applyCorsHeaders(req, res)
	if (!res.getHeader('X-Content-Type-Options')) {
		res.setHeader('X-Content-Type-Options', 'nosniff')
	}
	// Keep explicit header-setting here so even direct handler invocation sends clickjacking protection.
	res.setHeader('X-Frame-Options', 'SAMEORIGIN')
	res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; img-src 'self' data:; font-src 'self' data: https://maxcdn.bootstrapcdn.com; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'")

	if (req.body.eqn) {
		res.render('app/calc', {
			output: mathjs.eval(req.body.eqn)
		})
	} else {
		res.render('app/calc', {
			output: 'Enter a valid math string like (3+3)*2'
		})
	}
}

module.exports.listUsersAPI = function (req, res) {
	db.User.findAll({}).then(users => {
		res.status(200).json({
			success: true,
			users: users
		})
	})
}

module.exports.bulkProductsLegacy = function (req,res){
	// TODO: Deprecate this soon
	if(req.files.products){
		var products = serialize.unserialize(req.files.products.data.toString('utf8'))
		products.forEach( function (product) {
			var newProduct = new db.Product()
			newProduct.name = product.name
			newProduct.code = product.code
			newProduct.tags = product.tags
			newProduct.description = product.description
			newProduct.save()
		})
		res.redirect('/app/products')
	}else{
		res.render('app/bulkproducts',{messages:{danger:'Invalid file'},legacy:true})
	}
}

module.exports.bulkProducts =  function(req, res) {
	if (req.files.products && req.files.products.mimetype=='text/xml'){
		var products = libxmljs.parseXmlString(req.files.products.data.toString('utf8'), {noent:true,noblanks:true})
		products.root().childNodes().forEach( product => {
			var newProduct = new db.Product()
			newProduct.name = product.childNodes()[0].text()
			newProduct.code = product.childNodes()[1].text()
			newProduct.tags = product.childNodes()[2].text()
			newProduct.description = product.childNodes()[3].text()
			newProduct.save()
		})
		res.redirect('/app/products')
	}else{
		res.render('app/bulkproducts',{messages:{danger:'Invalid file'},legacy:false})
	}
}
