var mypbkdf2 = null;
var sjclPbkdf2Timeout = null;

var passwordLib = (function () {
	"use strict";



	async function calculatePasswordSjclPbkdf2(originalPassword, url, options) {

		if (originalPassword.trim() === '') {
				// Skip calculation for an empty password
				return Promise.resolve('');
			}

			var resolve = () => {
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
			console.log('calculated');
			return calculatePasswordInternal(hexKey, salt, intOptions);


		};

			return Promise.resolve(resolve());

	}


	function calculatePassword(originalPassword, url, options) {
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
				resolve(calculatePasswordInternal(key, salt, intOptions));
			};
			mypbkdf2.deriveKey(options.statusCallback, intResultCallback);

		});

	}

	function calculatePasswordInternal(key, salt, options) {
		var base64 = hexToBase64(key);

		// Generate actual password (based on encrypted password), using the given criteria
		var typeCount = 0;
		if (options.smallLetters)
			typeCount++;
		if (options.capitalLetters)
			typeCount++;
		if (options.numbers)
			typeCount++;
		if (options.specialChars)
			typeCount++;

		var prefix = "";
		var newPassword = "";
		var specialCharsListStart = salt.length % options.specialCharList.length;

		var smallLettersAdded = false;
		var capitalLettersAdded = false;
		var numbersAdded = false;
		var specialCharsAdded = false;
		var charAdded = false;

		for (var i = 0; i < base64.length; i++) {
			var curChar = base64.charAt(i);
			var charCode = curChar.charCodeAt();

			charAdded = false;


			if (typeCount > 0) {
				// Generate prefix, containing one of each
				if (options.smallLetters && !smallLettersAdded && charCode >= 97
						&& charCode <= 122) {
					prefix += curChar;
					smallLettersAdded = true;
					typeCount--;
					charAdded = true;
				} else if (options.capitalLetters && !capitalLettersAdded && charCode >= 65
						&& charCode <= 90) {
					prefix += curChar;
					capitalLettersAdded = true;
					typeCount--;
					charAdded = true;
				} else if (options.numbers && !numbersAdded && charCode >= 48
						&& charCode <= 57) {
					prefix += curChar;
					numbersAdded = true;
					typeCount--;
					charAdded = true;
				} else if (options.specialChars && !specialCharsAdded
						&& (charCode == 43 || charCode == 47 || charCode == 61)) {
					prefix += options.specialCharList.charAt((specialCharsListStart + i)
							% options.specialCharList.length);
					specialCharsAdded = true;
					typeCount--;
					charAdded = true;
				}

			}

			if (!charAdded) {
				if (options.smallLetters && charCode >= 97 && charCode <= 122) {
					newPassword += curChar;
				} else if (options.capitalLetters && charCode >= 65 && charCode <= 90) {
					newPassword += curChar;
				} else if (options.numbers && charCode >= 48 && charCode <= 57) {
					newPassword += curChar;
				} else if (options.specialChars
						&& (charCode == 43 || charCode == 47 || charCode == 61)) {
					newPassword += options.specialCharList
							.charAt((specialCharsListStart + i)
									% options.specialCharList.length);
				}
			}

			if (typeCount == 0 && prefix.length + newPassword.length >= options.length) {
				break;
			}

		}

		return (prefix + newPassword).substring(0, options.length);

	}

	/**
	 * @deprecated old version, obsolete, use calculatePassword() instead
	 */
	function calculatePasswordOld(originalPassword, url, length, smallLetters, capitalLetters, numbers, specialChars, specialCharList, resultCallback){
		if (originalPassword.trim() == '') {
			// Skip calculation for an empty password
			return '';
		}

		var domain = getDomain(url);
		var salt = getBaseUrl(domain);
		var saltedPassword = salt+originalPassword;

		var newPassword = hex_sha1(saltedPassword);
		newPassword = newPassword.substring(0,length);

		var moduloSpecialChars = saltedPassword.length % (length - 3) + 3;
		var moduloLargeChars = saltedPassword.length % 2 +2;

		var specialCharsListStart = salt.length % specialCharList.length;

		if (!numbers){
			var tempPassword = '';
			for(i=0;i<newPassword.length; i++){
				if (!isNaN(newPassword.substring(i,i+1))){
					tempPassword += String.fromCharCode(97+parseInt(newPassword.charAt(i)));
				} else {
					tempPassword += newPassword.charAt(i);
				}
			}
			newPassword = tempPassword;
		}

		if (!smallLetters){
			if (capitalLetters){
				newPassword = newPassword.toUpperCase();
			} else if (numbers){
				tempPassword = '';
				for(var i=0;i<newPassword.length; i++){
					tempPassword += newPassword.charCodeAt(i) % 10;
				}
				newPassword = tempPassword;
			}
		}
		if (capitalLetters && smallLetters){
			tempPassword = '';
			var c = 0;
			for(var i=0;i<newPassword.length; i++){
				var character = newPassword.charAt(i);
				if (isNaN(character)){
					if (c % moduloLargeChars == 0)
						tempPassword += character.toUpperCase();
					else
						tempPassword += character;
					c++;
				} else {
					tempPassword += character;
				}
			}
			newPassword = tempPassword;
		}

		if (specialChars){
			tempPassword = '';
			for(var i=0;i<newPassword.length; i++){
				if (i>0 && i % moduloSpecialChars == 0){
					tempPassword += specialCharList.charAt((specialCharsListStart*i)%specialCharList.length);
				} else {
					tempPassword += newPassword.charAt(i);
				}
			}
			newPassword = tempPassword;

		}

		resultCallback(newPassword);

	}

	function randomHash() {
		var out = sjcl.hash.sha256.hash(sjcl.random.randomWords(1)[0]);
		return sjcl.codec.hex.fromBits(out);
	}


	/**
   * Returns the base url from a given domain.
	 * The base url is the domain name without the superdomain, e.g. for www.foobar.com it returns foobar.
	 *
	 * @param domain Domain to parse
	 * @return base url of given domain
	 *
	 */
	function getBaseUrl(domain) {

		if (domain && domain !== '') {

			var parts = domain.split('.').reverse();
			var cnt = parts.length;
			if (cnt >= 3) {
				// see if the second level domain is a common SLD.
				if (parts[1].match(/^(com|edu|gov|net|mil|org|nom|co|name|info|biz)$/i)) {
					return parts[2];
				} else {
					return parts[1];
				}
			} else if (cnt >= 2) {
				return parts[1];
			} else {
				return domain;
			}
		}

		return domain;
	}

	/**
	 * Returns the domain name for a given url
	 *
	 * @param origUrl	original url to be parsed
	 * @return domain for given origUrl
	 *
	 */
	function getDomain(origUrl) {
		if (!origUrl)
			return origUrl;

		var parser = document.createElement('a');

		var origUrlLower = origUrl.toLowerCase().replace('&nbsp;', '');
		var url = origUrlLower;

		parser.href = url;

		var host = window.location.hostname;
		if ((parser.host.indexOf(host) >= 0 && origUrlLower.indexOf(host) == -1)) {
			// This is handled as a relative url, change it to an absolute one
			url = 'http://'+url;
			parser.href = url;
		}

		return parser.hostname;
	}

	/**
	 * Returns the default options used for the calculation of the password.$
	 * @return Object containing the default options.
	 */
	var getDefaultOptions = () => {
		return {
			length: 20,
			smallLetters: true,
			capitalLetters: true,
			numbers: true,
			specialChars: true,
			specialCharList: '][?/<~#`!@$%^&*()+=}|:";\',>{',
			iterations: 100,
			statusCallback: undefined
		};
	}

	return {
		calculatePasswordSjclPbkdf2: calculatePasswordSjclPbkdf2,
		calculatePassword: calculatePassword,
		calculatePasswordOld: calculatePasswordOld,
		randomHash: randomHash,
		getBaseUrl: getBaseUrl,
		getDomain: getDomain,
		getDefaultOptions: getDefaultOptions
	};

}());