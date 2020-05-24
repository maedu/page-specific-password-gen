export interface Options {
	length: number,
	smallLetters: boolean,
	capitalLetters: boolean,
	numbers: boolean,
	specialChars: boolean,
	specialCharList: string,
	iterations: number,
    statusCallback: any,
    verbose?: boolean
}