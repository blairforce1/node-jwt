'use strict';

var jwt = require('../lib/jwt'),
	fs = require('fs'),
	path = require('path'),
	base64Url = require('../lib/base64Url');

describe('JSON Web Token', function() {
	describe('using Symmetric Key', function() {
		var rawToken = 'ZXlKMGVYQWlPaUpLVjFRaUxDSmhiR2NpT2lKSVV6STFOaUo5LmV5SnBjM01pT2lKcWIyNXVlV0lpTENKaGRXUWlPaUoxY200NllYVmthV1Z1WTJVaUxDSmxlSEFpT2pFek1EQTRNVGt6T0RBc0ltaDBkSEE2THk5bGVHRnRjR3hsTG1OdmJTOXBjMTl5YjI5MElqcDBjblZsZlEuUkRWMDVMalZFMzgzNXY0NFFyNjZ0dG03ek9zWGV1Qm5tVUlSMC02YkZGTQ';
		var key = 'pSXeMohHqCpxD3bFrpDLFx9JtKZTDcvn0Tfyd2HZFhw=';
		var token = {
				header: { typ: 'JWT' },
				payload: { iss: 'jonnyb', aud: 'urn:audience', exp: 1300819380, "http://example.com/is_root": true }
			};

		describe('when decoding', function() {
			var decodedToken = jwt.decodeToken(rawToken);

			it('should decode the header', function() {
				decodedToken.header.typ.should.equal('JWT');
				decodedToken.header.alg.should.equal('HS256');
			});

			it('should decode the payload', function() {
				decodedToken.payload.iss.should.equal('jonnyb');
				decodedToken.payload.aud.should.equal('urn:audience');
				decodedToken.payload.exp.should.equal(1300819380);
			});

			it('should validate signature', function() {
				jwt.isSignatureValid(decodedToken, 'HS256', key).should.be.true;
			});

			it ('should validate the audience', function() {
				jwt.isAudienceValid(decodedToken, 'urn:audience').should.be.true;
				jwt.isAudienceValid(decodedToken, 'urn:incorrect').should.be.false;
			});

			it('should validate expiry', function() {
				jwt.isExpired(decodedToken).should.be.true;
			});

			describe('when algorithms do not match', function() {
				it('should not validate the signature', function() {
					jwt.isSignatureValid(decodedToken, 'RS256', key).should.be.false;
				});
			});

			describe('when signatures do not match', function() {
				var badDecodedToken =  {
						header: { typ: 'JWT', alg: 'HS256' },
						payload: { iss: 'jonnyb', aud: 'urn:audience', exp: 1300819380, 'http://example.com/is_root': true }, 
						signature: 'TOO-SHORT',
						bytesToSign: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb25ueWIiLCJhdWQiOiJ1cm46YXVkaWVuY2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
					};

				it('should not validate the signature', function() {
					jwt.isSignatureValid(badDecodedToken, 'HS256', key).should.be.false;
				});
			});
		});

		describe('when encoding', function() {
			it('should encode and sign the token', function() {
				var encodedToken = jwt.encodeToken(token, 'HS256', key);
				encodedToken.should.equal(rawToken);
			});
		});
	});

	describe('using PKI', function() {
		var rawToken = 'ZXlKMGVYQWlPaUpLVjFRaUxDSmhiR2NpT2lKU1V6STFOaUo5LmV5SnBjM01pT2lKcWIyNXVlV0lpTENKaGRXUWlPaUoxY200NllYVmthV1Z1WTJVaUxDSmxlSEFpT2pFek1EQTRNVGt6T0RBc0ltaDBkSEE2THk5bGVHRnRjR3hsTG1OdmJTOXBjMTl5YjI5MElqcDBjblZsZlEuSmVTQ3ZjOHRnemlabFc0SGJjaTYwRm04VU1TWVJjUzJ0YU5HUFVYdlhIV0tGOUFmUVJIZVJxQUN5bWtqV2VCOTljaTZ3STBuMnpvdTktZXd2RDNkWm4yd2ZiY1A2dlJDeHhPOTRpbHJJTC1IaktYYUYyS1UwemYxT045eTZ0Ymw0SkJtQ3ZpM1JKekhncnVqeUR6QWNUMjVla0V3R0diSV84cjlXUkRYZ1ZhLXU5OV9UVWVHZDhTbDdyNWdNNFg5bktaUWlxai1zSHJGSVlQaEpnTDkzLXhUWUFtYUhZTWxiMlhBVEJPaF9yVVp4OE5DRXRISEhkQlE0QzJrLURXZm1rN01jTlJuMC0xVHJTQVVnVmpWUWh2QkpPanBmem9mckZhYTVTWjc1aU9KcDdkZHJOOUl6YmU2cXIxRkYyMV9FRERpcmJQbS0tWEtjS2tEVjdwcGdB';
		var key = fs.readFileSync(path.resolve(path.join(__dirname, '..', 'certs', 'server.pem')));
		var privateKey = fs.readFileSync(path.resolve(path.join(__dirname, '..', 'certs', 'server.key')));
		var token = {
				header: { typ: 'JWT' },
				payload: { iss: 'jonnyb', aud: 'urn:audience', exp: 1300819380, "http://example.com/is_root": true }
			};

		describe('when decoding', function() {
			var decodedToken = jwt.decodeToken(rawToken);

			it('should decode the header', function() {
				decodedToken.header.typ.should.equal('JWT');
				decodedToken.header.alg.should.equal('RS256');
			});

			it('should decode the payload', function() {
				decodedToken.payload.iss.should.equal('jonnyb');
				decodedToken.payload.aud.should.equal('urn:audience');
				decodedToken.payload.exp.should.equal(1300819380);
			});

			it('should validate signature', function() {
				jwt.isSignatureValid(decodedToken, 'RS256', key).should.be.true;
			});

			describe('when algorithms do not match', function() {
				it('should not validate the signature', function() {
					jwt.isSignatureValid(decodedToken, 'HS256', key).should.be.false;
				});
			});
		});



		describe('when encoding', function() {
			it('should encode and sign the token', function() {
				var encodedToken = jwt.encodeToken(token, 'RS256', privateKey);
				encodedToken.should.equal(rawToken);
			});
		});
	});

	describe('When a hacker tries to exploit RS256 key', function() {
		var key = fs.readFileSync(path.resolve(path.join(__dirname, '..', 'certs', 'server.pem')));
		var token = {
				header: { typ: 'JWT' },
				payload: { iss: 'jonnyb', aud: 'urn:audience', exp: 1300819380, "http://example.com/is_root": true }
			};

		var fakedToken = jwt.encodeToken(token, 'HS256', base64Url.encode(key));

		it('should not validate the signature', function() {
			var decodedToken = jwt.decodeToken(fakedToken);
			jwt.isSignatureValid(decodedToken, 'RS256', key).should.be.false;
		});
	});
});

