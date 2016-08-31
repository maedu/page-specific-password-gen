# page-specific-password-gen

A small library which allows the generation of page specific passwords.

## Code Example

```javascript
var originalPassword = 'abcd1234';
var url = 'http://www.foo.com';

passwordLib.calculatePassword(originalPassword, url).then(function(generatedPassword) {
  console.log('generated password', generatedPassword);
});

```

## Motivation

People who regularely surf the internet usually have various accounts on various websites. 
Unfortunately most people are not capable to remember a different password for the different websites
so they tend to reuse the same password over and over again.

When one registers or logins to a website, one sends the password in plaintext to that respective site.
It is then in the responsibility of the owner of the website to store that password safely and in an encrypted
way so no one (not even them) can take a look at it.

Unfortunately not all the hosts of websites are really responsible in that way and as a user one has no idea how they 
are storing the passwords or what they are doing with them. In theory they could store them in a text file and sell it to the highest bidder.

This library comes by this problem in a way, that it allows to generate (or actually encrypt) website specific passwords.

The input is the password given by the user and the url of the website.
It then generates a hash-like password which is specific for that combination.

The process is based on [PBKDF2], where it uses parts of the domain as the salt value.
After the encryption there is some post-processing going on, which ensures that the generated password 
is according to the parameters defined by the user (such as length, including of small letters, capital letters, numbers etc).
<!--
This library can be used, to generate website specific passwords.  
This way a user can create different passwords for different domains using the same password as an input. 
With that the 

The process for that is quite simple:  

It takes the domain as a salt value, combines it with the password and encrypts it.
-->
## Installation

First install it with bower:  
`bower install -S page-specific-password-gen`

Then include it in your html page:  
`<script type="text/javascript" src="path/to/js/page-specific-password-gen.js"></script>`

You can also use the minified version instead:  
`<script type="text/javascript" src="path/to/js/page-specific-password-gen.min.js"></script>`

<!--
## API Reference

Depending on the size of the project, if it is small and simple enough the reference docs can be added to the README. For medium size to larger projects it is important to at least provide a link to where the API reference docs live.
-->

## Tests

Tests are done with [Jasmine]:  
[Tests for src]  
[Tests for dist]  
[Tests for dist (minified)]  

<!--## Contributors

Let people know how they can dive into the project, include important links to things like issue trackers, irc, twitter accounts if applicable.
-->

## License

The MIT License (MIT)

Copyright (c) 2016 Matthias Spinner

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

[PBKDF2]: https://en.wikipedia.org/wiki/PBKDF2
[Jasmine]: http://jasmine.github.io/2.4/introduction.html
[Tests for src]: test/index_src.html
[Tests for dist]: test/index_dist.html
[Tests for dist (minified)]: test/index_dist_min.html
