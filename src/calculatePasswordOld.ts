export const getBaseUrl = (domain: string): string => {

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