'use strict';

var crypto = require('crypto'),
	base64Url = require('./base64Url');

(function() {
	var api = {
		HS256: {
			verify: function verify(bytesToSign, key, signature) {
				return this.sign(bytesToSign, key) === signature;
			},
			sign: function sign(bytesToSign, key) {
				return base64Url.urlEncode(crypto.createHmac('sha256', base64Url.decode(key)).update(bytesToSign).digest('base64'));
			}
		},
		RS256: {
			verify: function verify(bytesToSign, key, signature) {
				return crypto.createVerify('RSA-SHA256').update(bytesToSign).verify(key, signature, 'base64');
			},
			sign: function sign(bytesToSign, key) {
				return base64Url.urlEncode(crypto.createSign('RSA-SHA256').update(bytesToSign).sign(key, 'base64'));
			}
		}
	};

	module.exports = api;
}());
