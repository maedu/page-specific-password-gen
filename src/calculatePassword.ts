import { Options, getDefaultOptions } from "./getDefaultOptions";
import { getBaseUrl } from "./getBaseUrl";
import { getDomain } from "./getDomain";
import * as pbkdf2 from './crypt/pbkdf2';

export const calculatePassword = (originalPassword: string, url: string, options: Options): Promise<any> => {
	return new Promise(function(resolve, reject) {
		var intOptions = getDefaultOptions();

		if (typeof options !== 'undefined') {
			// Merge the options
			for (var attrname in options) {
				intOptions[attrname] = options[attrname];
			}
		}

		if (options.verbose)
			console.log('calculatePassword', 'url:', url, 'options:', intOptions);


		if (originalPassword.trim() == '') {
			// Skip calculation for an empty password
			resolve('');
			return;
		}

		var domain = getDomain(url);
		var salt = getBaseUrl(domain);

		if (options.verbose)
			console.log('calculatePassword, salt:', salt);

		// Encrypt password using the original password and the given salt value
		var iterations = intOptions.iterations + (salt.length + originalPassword.length + 1);

		if (mypbkdf2 != null)
			mypbkdf2.stop();

		mypbkdf2 = new PBKDF2(originalPassword, salt, iterations, 128);

		var intResultCallback = function (key) {
			calculatePasswordInternal(key, salt, intOptions, resolve, reject);
		};
		mypbkdf2.deriveKey(options.statusCallback, intResultCallback);

	});

}