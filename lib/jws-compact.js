'use strict';

var crypto = require('crypto'),
	base64Url = require('./base64Url');

(function() {

	function allCharCompare(secret, comparison) {
		if (secret.length !== comparison.length) {
			return false;
		}
		var result = 0;
		for (var i = 0; i < secret.length; i++) {
			/*jshint bitwise:false */
			result |= secret.charCodeAt(i) ^ comparison.charCodeAt(i);
		}
		return 0 === result;
	}

	var api = {
		HS256: {
			verify: function verify(bytesToSign, key, signature) {
				return allCharCompare(this.sign(bytesToSign, key), signature);
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
