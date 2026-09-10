var db = require('../models')
var bCrypt = require('bcrypt')
var crypto = require('crypto')
const exec = require('child_process').exec;
var mathjs = require('mathjs')
var libxmljs = require("libxmljs");
var serialize = require("node-serialize")
const Op = db.Sequelize.Op

function normalizeProductSearchTerm(name) {
	return String(name || '')
		.trim()
		.replace(/[\u0000-\u001f\u007f]/g, '')
		.replace(/[<>]/g, '')
		.slice(0, 100)
}

function setProductsPageSecurityHeaders(res) {
	res.set('Content-Security-Policy', "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; font-src 'self' https://maxcdn.bootstrapcdn.com data:; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
}

function normalizeProductId(value) {
	var id = parseInt(value, 10)

	if (!Number.isInteger(id) || id < 1) {
		return 0
	}

	return id
}

function sanitizeProductText(value, maxLength) {
	return String(value == null ? '' : value)
		.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '')
		.replace(/<\/?style\b[^>]*>/gi, '')
		.replace(/[<>{}]/g, '')
		.slice(0, maxLength)
}

function sanitizeProductInput(product) {
	product = product || {}

	return {
		id: normalizeProductId(product.id),
		name: sanitizeProductText(product.name, 255),
		code: sanitizeProductText(product.code, 255).replace(/[^a-zA-Z0-9._\- ]/g, ''),
		description: sanitizeProductText(product.description, 65535),
		tags: sanitizeProductText(product.tags, 255).replace(/[^a-zA-Z0-9,._\- ]/g, '')
	}
}

function generateCsrfToken() {
	return crypto.randomBytes(32).toString('hex')
}

function getSessionCsrfToken(req) {
	if (!req.session.csrfToken) {
		req.session.csrfToken = generateCsrfToken()
	}

	return req.session.csrfToken
}

function tokensMatch(expectedToken, providedToken) {
	if (typeof expectedToken !== 'string' || typeof providedToken !== 'string') {
		return false
	}

	var expectedBuffer = Buffer.from(expectedToken)
	var providedBuffer = Buffer.from(providedToken)

	if (expectedBuffer.length !== providedBuffer.length) {
		return false
	}

	return crypto.timingSafeEqual(expectedBuffer, providedBuffer)
}

module.exports.modifyProductCsrfProtection = function (req, res, next) {
	var csrfToken = getSessionCsrfToken(req)
	res.locals.csrfToken = csrfToken

	if (req.method !== 'POST') {
		return next()
	}

	if (!tokensMatch(csrfToken, req.body._csrf)) {
		req.flash('danger', 'Invalid request')
		setProductsPageSecurityHeaders(res)
		return res.status(403).render('app/modifyproduct', {
			output: {
				product: sanitizeProductInput(req.body)
			},
			csrfToken: csrfToken
		})
	}

	return next()
}

module.exports.userSearch = function (req, res) {
	var login = String(req.body.login || '')
	var query = 'SELECT name,id FROM Users WHERE login = :login'
	db.sequelize.query(query, {
		replacements: {
			login: login
		},
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
	exec('ping -c 2 ' + req.body.address, function (err, stdout, stderr) {
		output = stdout + stderr
		res.render('app/ping', {
			output: output
		})
	})
}

module.exports.listProducts = function (req, res) {
	db.Product.findAll().then(products => {
		setProductsPageSecurityHeaders(res)
		output = {
			products: products
		}
		res.render('app/products', {
			output: output
		})
	})
}

module.exports.productSearch = function (req, res) {
	const searchTerm = normalizeProductSearchTerm(req.body.name)
	db.Product.findAll({
		where: {
			name: {
				[Op.like]: '%' + searchTerm + '%'
			}
		}
	}).then(products => {
		setProductsPageSecurityHeaders(res)
		output = {
			products: products,
			searchTerm: searchTerm
		}
		res.render('app/products', {
			output: output
		})
	})
}

module.exports.modifyProduct = function (req, res) {
	var productId = normalizeProductId(req.query.id)

	if (!productId) {
		output = {
			product: sanitizeProductInput({})
		}
		setProductsPageSecurityHeaders(res)
		res.render('app/modifyproduct', {
			output: output
		})
	} else {
		db.Product.find({
			where: {
				'id': productId
			}
		}).then(product => {
			if (!product) {
				product = {}
			}
			output = {
				product: sanitizeProductInput(product)
			}
			setProductsPageSecurityHeaders(res)
			res.render('app/modifyproduct', {
				output: output
			})
		})
	}
}

module.exports.modifyProductSubmit = function (req, res) {
	var sanitizedProduct = sanitizeProductInput(req.body)
	db.Product.find({
		where: {
			'id': sanitizedProduct.id
		}
	}).then(product => {
		if (!product) {
			product = new db.Product()
		}
		product.code = sanitizedProduct.code
		product.name = sanitizedProduct.name
		product.description = sanitizedProduct.description
		product.tags = sanitizedProduct.tags
		product.save().then(p => {
			if (p) {
				req.flash('success', 'Product added/modified!')
				res.redirect('/app/products')
			}
		}).catch(err => {
			output = {
				product: sanitizeProductInput(product)
			}
			req.flash('danger',err)
			setProductsPageSecurityHeaders(res)
			res.render('app/modifyproduct', {
				output: output
			})
		})
	})
}

module.exports.userEdit = function (req, res) {
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
			req.flash('success',"Updated successfully")
			res.render('app/useredit', {
				userId: req.body.id,
				userEmail: req.body.email,
				userName: req.body.name,
			})
		})
	})
}

module.exports.redirect = function (req, res) {
	const redirectUrl = typeof req.query.url === 'string' ? req.query.url.trim() : ''

	if (!redirectUrl) {
		res.send('invalid redirect url')
		return
	}

	try {
		const baseUrl = new URL(req.protocol + '://' + req.get('host'))
		const targetUrl = new URL(redirectUrl, baseUrl)

		if (!redirectUrl.startsWith('/') || redirectUrl.startsWith('//') || targetUrl.origin !== baseUrl.origin) {
			res.send('invalid redirect url')
			return
		}

		res.redirect(targetUrl.pathname + targetUrl.search + targetUrl.hash)
	} catch (err) {
		res.send('invalid redirect url')
	}
}

module.exports.calc = function (req, res) {
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
