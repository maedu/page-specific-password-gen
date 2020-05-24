import { Options } from './getDefaultOptions';
import { EncodeDecode } from './EncodeDecode';

export const calculatePasswordInternal = (key: string, salt: string, options: Options, resultCallback: any, rejectCallback: any): void => {

	var base64 = EncodeDecode.b64DecodeUnicode(key);

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
		var charCode = curChar.charCodeAt(0);

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

	resultCallback((prefix + newPassword).substring(0, options.length));

}