'use strict';

var jws = require('./jws-compact'),
	base64Url = require('./base64Url'),
	util = require('util');

(function() {
	var api = {
		decodeToken: function(rawToken) {
			var decodedToken = base64Url.decode(rawToken).toString('UTF-8');
			var tokenSegments = decodedToken.split('.');

			return {
				header: JSON.parse(base64Url.decode(tokenSegments[0])),
				payload: JSON.parse(base64Url.decode(tokenSegments[1])),
				signature: tokenSegments[2],
				bytesToSign: tokenSegments[0] + '.' + tokenSegments[1]
			};
		},

		encodeToken: function(token, key) {
			var encodedHeader = base64Url.encode(JSON.stringify(token.header));
			var encodedPayload = base64Url.encode(JSON.stringify(token.payload));
			var bytesToSign = util.format('%s.%s', encodedHeader, encodedPayload);
			var signedBytes = jws[token.header.alg].sign(bytesToSign, key);

			var tokenParts = util.format('%s.%s.%s', encodedHeader, encodedPayload, signedBytes);
			return base64Url.encode(tokenParts);
		},

		isExpired: function(token) {
			var epoch = parseInt(token.payload.exp, 10);
			return new Date() > new Date(epoch * 1000);
		},

		isAudienceValid: function(token, audienceUrn) {
			return token.payload.aud === audienceUrn;
		},

		isSignatureValid: function (token, key) {
			return jws[token.header.alg].verify(token.bytesToSign, key, token.signature);
		},
	};

	module.exports = api;
}());