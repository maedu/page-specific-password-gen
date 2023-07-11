export function calculatePassword(originalPassword: string, url: string, options: Options): Promise<string>
export function calculatePasswordOld(originalPassword: string, url: string, length: number, smallLetters: boolean, capitalLetters: boolean, numbers: boolean, specialChars: boolean, specialCharList: string, resultCallback: PasswordCallback): void; function getBaseUrl(domain: string): string
export function getDomain(origUrl: string): string
export function getBaseUrl(domain: string): string
export function getDefaultOptions(): Options