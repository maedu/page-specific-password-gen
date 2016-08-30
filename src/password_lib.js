var mypbkdf2 = null;

var passwordLib = (function () {
	"use strict";
	return {
		calculatePassword: calculatePassword,
		calculatePasswordOld: calculatePasswordOld,
		getBaseUrl: getBaseUrl,
		getDomain: getDomain
	};

	function calculatePassword(originalPassword, url, length, smallChars, capitalChars, numbers, specialChars, specialCharList, statusCallback, resultCallback, baseIterations) {

		if (originalPassword.trim() == '') {
			// Skip calculation for an empty password
			resultCallback('');
			return;
		}

		var domain = getDomain(url);
		var salt = getBaseUrl(domain);

		console.log('calculatePassword, salt:', salt);

		// Encrypt password using the original password and the given salt value
		var iterations = baseIterations + (salt.length + originalPassword.length + 1);

		if (mypbkdf2 != null)
			mypbkdf2.stop();

		mypbkdf2 = new PBKDF2(originalPassword, salt, iterations, 128);

		var intResultCallback = function(key) {
			calculatePasswordInternal(key, length, salt, smallChars, capitalChars, numbers, specialChars, specialCharList, resultCallback);
		};
		mypbkdf2.deriveKey(statusCallback, intResultCallback);

	}

	function calculatePasswordInternal(key, length, salt, smallChars, capitalChars, numbers, specialChars, specialCharList, resultCallback) {
		var base64 = hexToBase64(key);

		// Generate actual password (based on encrypted password), using the given criteria
		var typeCount = 0;
		if (smallChars)
			typeCount++;
		if (capitalChars)
			typeCount++;
		if (numbers)
			typeCount++;
		if (specialChars)
			typeCount++;

		var prefix = "";
		var newPassword = "";
		var specialCharsListStart = salt.length % specialCharList.length;

		var smallCharsAdded = false;
		var capitalCharsAdded = false;
		var numbersAdded = false;
		var specialCharsAdded = false;
		var charAdded = false;

		for (var i = 0; i < base64.length; i++) {
			var curChar = base64.charAt(i);
			var charCode = curChar.charCodeAt();

			charAdded = false;


			if (typeCount > 0) {
				// Generate prefix, containing one of each
				if (smallChars && !smallCharsAdded && charCode >= 97
						&& charCode <= 122) {
					prefix += curChar;
					smallCharsAdded = true;
					typeCount--;
					charAdded = true;
				} else if (capitalChars && !capitalCharsAdded && charCode >= 65
						&& charCode <= 90) {
					prefix += curChar;
					capitalCharsAdded = true;
					typeCount--;
					charAdded = true;
				} else if (numbers && !numbersAdded && charCode >= 48
						&& charCode <= 57) {
					prefix += curChar;
					numbersAdded = true;
					typeCount--;
					charAdded = true;
				} else if (specialChars && !specialCharsAdded
						&& (charCode == 43 || charCode == 47 || charCode == 61)) {
					prefix += specialCharList.charAt((specialCharsListStart + i)
							% specialCharList.length);
					specialCharsAdded = true;
					typeCount--;
					charAdded = true;
				}

			}

			if (!charAdded) {
				if (smallChars && charCode >= 97 && charCode <= 122) {
					newPassword += curChar;
				} else if (capitalChars && charCode >= 65 && charCode <= 90) {
					newPassword += curChar;
				} else if (numbers && charCode >= 48 && charCode <= 57) {
					newPassword += curChar;
				} else if (specialChars
						&& (charCode == 43 || charCode == 47 || charCode == 61)) {
					newPassword += specialCharList
							.charAt((specialCharsListStart + i)
									% specialCharList.length);
				}
			}

			if (typeCount == 0 && prefix.length + newPassword.length >= length) {
				break;
			}

		}

		resultCallback(prefix + newPassword.substring(0, length - prefix.length));

	}

	/**
	 * Old version, obsolete, use calculatePassword() instead
	 */
	function calculatePasswordOld(originalPassword, url, length, smallChars, capitalChars, numbers, specialChars, specialCharList, resultCallback){
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

		if (!smallChars){
			if (capitalChars){
				newPassword = newPassword.toUpperCase();
			} else if (numbers){
				tempPassword = '';
				for(var i=0;i<newPassword.length; i++){
					tempPassword += newPassword.charCodeAt(i) % 10;
				}
				newPassword = tempPassword;
			}
		}
		if (capitalChars && smallChars){
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



	function getBaseUrl(domain) {

		if (domain !== '') {

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

		return '';
	}

	function getDomain(origUrl) {
		var parser = document.createElement('a');

		var origUrlLower = origUrl.toLowerCase().replace('&nbsp;', '');
		var url = origUrlLower;

		parser.href = url;

		if ((parser.host.indexOf('magic-key') >= 0 && origUrlLower.indexOf('magic-key') == -1)
				|| (parser.host.indexOf('localhost') >= 0 && origUrlLower.indexOf('localhost') == -1)) {
			// This is handled as a relative url, change it to an absolute one
			url = 'http://'+url;
			parser.href = url;
		}

		return parser.hostname;
	}


}());