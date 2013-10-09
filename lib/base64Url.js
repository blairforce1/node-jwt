
(function() {
	var api = {
		encode: function(data) {
			return this.urlEncode(new Buffer(data).toString('base64'));
		},

		decode: function(base64UrlData) {
			base64UrlData = base64UrlData.replace(/-/g, '+').replace(/_/g, '/');
			switch (base64UrlData.length % 4) {
			case 2:
				base64UrlData += '==';
				break;
			case 3:
				base64UrlData += '=';
				break;
			}

			return new Buffer(base64UrlData, 'base64');
		},

		urlEncode: function (base64Data) {
			var result = base64Data.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
			return result;
		}
	};

	module.exports = api;
}());