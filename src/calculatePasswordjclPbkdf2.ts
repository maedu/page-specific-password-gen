import { getDomain } from './getDomain';
import { getBaseUrl } from './getBaseUrl';
import { Options, getDefaultOptions } from './getDefaultOptions';
import { calculatePasswordInternal } from './calculatePasswordInternal';


export const calculatePasswordSjclPbkdf2 = (originalPassword: string, url: string, options: Options): Promise<any> => {
	
	return new Promise(function(resolve, reject) {
		var sjclPbkdf2Timeout = null;
		if (sjclPbkdf2Timeout !== null) {
			clearTimeout(sjclPbkdf2Timeout);
		}

		if (originalPassword.trim() === '') {
			// Skip calculation for an empty password
			resolve('');
			return;
		}

		var callback = function() {
			var intOptions = getDefaultOptions();

			if (typeof options !== 'undefined') {
				// Merge the options
				for (var attrname in options) {
					intOptions[attrname] = options[attrname];
				}
			}

			if (options.verbose)
				console.log('calculatePassword', 'url:', url, 'options:', intOptions);

			var domain = getDomain(url);

			var out = sjcl.hash.sha256.hash(getBaseUrl(domain));
			var salt = sjcl.codec.hex.fromBits(out);
			if (options.salt) {
				salt = options.salt + salt;
			}

			if (options.verbose)
				console.log('calculatePassword, salt:', salt);

			// Encrypt password using the original password and the given salt value
			var iterations = intOptions.iterations + (salt.length + originalPassword.length + 1);


			var hmacSHA1 = function (key) {
				var hasher = new sjcl.misc.hmac( key, sjcl.hash.sha1 );
				this.encrypt = function () {
					return hasher.encrypt.apply( hasher, arguments );
				};
			};

			var passwordSalt = sjcl.codec.utf8String.toBits(salt);
			originalPassword = sjcl.codec.hex.toBits(originalPassword);
			var derivedKey = sjcl.misc.pbkdf2( originalPassword, passwordSalt, iterations, 512, hmacSHA1 );
			var hexKey = sjcl.codec.hex.fromBits( derivedKey );
			calculatePasswordInternal(hexKey, salt, intOptions, resolve, reject);
		};

		sjclPbkdf2Timeout = setTimeout(callback, 0);

	});

}