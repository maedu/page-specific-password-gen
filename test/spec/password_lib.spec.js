(function () {
  'use strict';


  describe('Tests for password_lib.getDefaultOptions', function () {

    it('should return correct default options', function () {
      var defaultOptions = passwordLib.getDefaultOptions();

      expect(defaultOptions.length).toBe(20);
      expect(defaultOptions.smallLetters).toBe(true);
      expect(defaultOptions.capitalLetters).toBe(true);
      expect(defaultOptions.numbers).toBe(true);
      expect(defaultOptions.specialChars).toBe(true);
      expect(defaultOptions.specialCharList).toBe('][?/<~#`!@$%^&*()+=}|:";\',>{');
      expect(defaultOptions.iterations).toBe(100);
    });

  });

  describe('Tests for password_lib.getDomain', function () {

    it('should return correct domain name', function () {
      var url = 'http://www.foo.com';
      var domainName = passwordLib.getDomain(url);
      var expected = 'www.foo.com';

      expect(domainName).toBe(expected);
    });

    it('should return correct domain name with full address', function () {
      var url = 'http://www.foo.com/abcdef?gh=ijk&lmno=qrst';
      var domainName = passwordLib.getDomain(url);
      var expected = 'www.foo.com';

      expect(domainName).toBe(expected);
    });

    it('should return correct domain name without protocl and subdomain', function () {
      var url = 'foo.com';
      var domainName = passwordLib.getDomain(url);
      var expected = 'foo.com';

      expect(domainName).toBe(expected);
    });

    it('should return correct domain name without protocol', function () {
      var url = 'www.foo.com';
      var domainName = passwordLib.getDomain(url);
      var expected = 'www.foo.com';

      expect(domainName).toBe(expected);
    });

    it('should return correct domain name with different subdomain', function () {
      var url = 'sub.foo.com';
      var domainName = passwordLib.getDomain(url);
      var expected = 'sub.foo.com';

      expect(domainName).toBe(expected);
    });

    it('should return correct domain name with just base name', function () {
      var url = 'foo';
      var domainName = passwordLib.getDomain(url);
      var expected = 'foo';

      expect(domainName).toBe(expected);
    });

    it('should return correct domain name with undefined', function () {
      var url = undefined;
      var domainName = passwordLib.getDomain(url);
      var expected = undefined;

      expect(domainName).toBe(expected);
    });

  });


  describe('Tests for password_lib.getBaseUrl', function () {

    it('should return correct base url', function () {
      var domain = 'www.foo.com';
      var baseUrl = passwordLib.getBaseUrl(domain);
      var expected = 'foo';

      expect(baseUrl).toBe(expected);
    });

    it('should return correct base url for multiple subdomains', function () {
      var domain = 'a.b.c.d.e.f.foo.com';
      var baseUrl = passwordLib.getBaseUrl(domain);
      var expected = 'foo';

      expect(baseUrl).toBe(expected);
    });

    it('should return correct base url for multiple superdomain', function () {
      var domain = 'a.b.c.d.e.f.foo.co.uk';
      var baseUrl = passwordLib.getBaseUrl(domain);
      var expected = 'foo';

      expect(baseUrl).toBe(expected);
    });

    it('should return correct base url for no subdomain', function () {
      var domain = 'foo.com';
      var baseUrl = passwordLib.getBaseUrl(domain);
      var expected = 'foo';

      expect(baseUrl).toBe(expected);
    });

    it('should return correct base url for base url', function () {
      var domain = 'foo';
      var baseUrl = passwordLib.getBaseUrl(domain);
      var expected = 'foo';

      expect(baseUrl).toBe(expected);
    });

    it('should return undefined for undefined', function () {
      var domain = undefined;
      var baseUrl = passwordLib.getBaseUrl(domain);
      var expected = undefined;

      expect(baseUrl).toBe(expected);
    });

    it('should return empty for empty', function () {
      var domain = '';
      var baseUrl = passwordLib.getBaseUrl(domain);
      var expected = '';

      expect(baseUrl).toBe(expected);
    });

  });

  describe('Tests for password_lib.calculatePasswordSjclPbkdf2', function () {

    jasmine.DEFAULT_TIMEOUT_INTERVAL = 100000;

    describe('Tests for default options with proper url', function () {
      var result = undefined;
      var expectedPassword = '6iF\'2X2UHvhwHMepdLq3';
      var url = 'http://www.foo.com/abcd?xyz';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();
      var statusCallbackCallCount = 0;

      beforeEach(function(done) {
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };
        passwordLib.calculatePasswordSjclPbkdf2(password, url, {verbose: true}).then(resultCallback);
      });

      it('should calculate password correctly', function () {
        expect(result).toBe(expectedPassword);
      });
    });

    describe('Tests for default options with proper url', function () {
      var result = undefined;
      var expectedPassword = '6iF\'2X2UHvhwHMepdLq3';
      var url = 'http://www.foo.com/abcd?xyz';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();

      beforeEach(function(done) {
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };

        passwordLib.calculatePasswordSjclPbkdf2(password, url, { verbose: true }).then(resultCallback);
      });

      it('should calculate password correctly', function () {
        expect(result).toBe(expectedPassword);
      });
    });

    describe('Tests for default options with different subdomain', function () {
      var result = undefined;
      var expectedPassword = '6iF\'2X2UHvhwHMepdLq3';
      var url = 'http://abd.foo.com';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();
      var statusCallbackCallCount = 0;

      beforeEach(function(done) {
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };
        passwordLib.calculatePasswordSjclPbkdf2(password, url, { verbose: true }).then(resultCallback);
      });

      it('should calculate password correctly', function () {
        expect(result).toBe(expectedPassword);
      });
    });

    describe('Tests for default options with different superdomain', function () {
      var result = undefined;
      var expectedPassword = '6iF\'2X2UHvhwHMepdLq3';
      var url = 'http://www.foo.ch';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();
      var statusCallbackCallCount = 0;

      beforeEach(function(done) {
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };
        passwordLib.calculatePasswordSjclPbkdf2(password, url, { verbose: true }).then(resultCallback);
      });

      it('should calculate password correctly', function () {
        expect(result).toBe(expectedPassword);
      });
    });

    describe('Tests for default options with different domain', function () {
      var result = undefined;
      var expectedPassword = 'j6J]aq2HMBSnMstrzipm';
      var url = 'http://www.foo2.com/abcd?xyz';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();
      var statusCallbackCallCount = 0;

      beforeEach(function(done) {
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };
        passwordLib.calculatePasswordSjclPbkdf2(password, url, { verbose: true }).then(resultCallback);
      });

      it('should calculate password correctly', function () {
        expect(result).toBe(expectedPassword);
      });
    });

    describe('Tests for default options without small chars', function () {
      var result = undefined;
      var expectedPassword = '6F\'2X2UHHML37P1SN7ZF';
      var url = 'foo';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();
      var statusCallbackCallCount = 0;

      beforeEach(function(done) {
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };
        passwordLib.calculatePasswordSjclPbkdf2(password, url, { smallLetters: false, verbose: true }).then(resultCallback);
      });

      it('should calculate password correclty', function () {
        expect(result).toBe(expectedPassword);
      });
    });

    describe('Tests for default options without capital chars', function () {
      var result = undefined;
      var expectedPassword = '6i\'22vhwepdq3n7lb17d';
      var url = 'foo';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();
      var statusCallbackCallCount = 0;

      beforeEach(function(done) {
        var statusCallback = function(percentage) {
          statusCallbackCallCount++;
        };
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };
        passwordLib.calculatePasswordSjclPbkdf2(password, url, { capitalLetters: false, verbose: true, statusCallback: statusCallback }).then(resultCallback);
      });

      it('should calculate password correclty', function () {
        expect(result).toBe(expectedPassword);
        
      });
    });

    describe('Tests for default options without numbers', function () {
      var result = undefined;
      var expectedPassword = 'iF\'XUHvhwHMepdLqnlbP';
      var url = 'foo';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();
      var statusCallbackCallCount = 0;

      beforeEach(function(done) {
        var statusCallback = function(percentage) {
          statusCallbackCallCount++;
        };
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };
        passwordLib.calculatePasswordSjclPbkdf2(password, url, { numbers: false, verbose: true, statusCallback: statusCallback }).then(resultCallback);
      });

      it('should calculate password correclty', function () {
        expect(result).toBe(expectedPassword);
        
      });
    });

    describe('Tests for default options without special chars', function () {
      var result = undefined;
      var expectedPassword = '6iF2X2UHvhwHMepdLq3n';
      var url = 'foo';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();
      var statusCallbackCallCount = 0;

      beforeEach(function(done) {
        var statusCallback = function(percentage) {
          statusCallbackCallCount++;
        };
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };
        passwordLib.calculatePasswordSjclPbkdf2(password, url, { specialChars: false, verbose: true, statusCallback: statusCallback }).then(resultCallback);
      });

      it('should calculate password correclty', function () {
        expect(result).toBe(expectedPassword);
        
      });
    });

    describe('Tests for default options with explicit special chars', function () {
      var result = undefined;
      var expectedPassword = '6iF;2X2UHvhwHMepdLq3';
      var url = 'foo';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();
      var statusCallbackCallCount = 0;

      beforeEach(function(done) {
        var statusCallback = function(percentage) {
          statusCallbackCallCount++;
        };
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };
        passwordLib.calculatePasswordSjclPbkdf2(password, url, { specialCharList: ';.', verbose: true, statusCallback: statusCallback }).then(resultCallback);
      });

      it('should calculate password correclty', function () {
        expect(result).toBe(expectedPassword);
        
      });
    });

    describe('Tests for default options with extra salt', function () {
      var result = undefined;
      var expectedPassword = 'rP5]uqZNwZo40VOcq6Ok';
      var url = 'foo';
      var password = 'bar';
      var salt = 'a9a363bd018715dca9e29212bd56196d0e89b4f943e958207ae91622e4cc10e1';
      console.log('salt', salt);
      var defaultOptions = passwordLib.getDefaultOptions();
      var statusCallbackCallCount = 0;

      beforeEach(function(done) {
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };
        passwordLib.calculatePasswordSjclPbkdf2(password, url, { salt: salt, verbose: true }).then(resultCallback);
      });

      it('should calculate password correclty', function () {
        expect(result).toBe(expectedPassword);
      });
    });


    fdescribe('Tests for default options with more iterations', function () {
      var result = undefined;
      var expectedPassword = '!Ed4%MBFGzZzBsuFTkaV';
      var url = 'foo';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();
      var statusCallbackCallCount = 0;

      beforeEach(function(done) {
        var resultCallback = function(generatedPassword) {
          console.log('resultCallback end');
          result = generatedPassword;
          done();
        };

        console.log('calculatePasswordSjclPbkdf2 start');
        passwordLib.calculatePasswordSjclPbkdf2(password, url, { iterations: 100000, verbose: true }).then(resultCallback);
        console.log('calculatePasswordSjclPbkdf2 after');

      });

      it('should calculate password correclty', function () {
        expect(result).toBe(expectedPassword);
      });
    });

    describe('Tests for length 0', function () {
      var result = undefined;
      var expectedPassword = '';
      var url = 'foo';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();
      var statusCallbackCallCount = 0;

      beforeEach(function(done) {
        var statusCallback = function(percentage) {
          statusCallbackCallCount++;
        };
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };
        passwordLib.calculatePasswordSjclPbkdf2(password, url, { length: 0, verbose: true, statusCallback: statusCallback }).then(resultCallback);
      });

      it('should calculate password correclty', function () {
        expect(result).toBe(expectedPassword);
        
      });
    });

    describe('Tests for length 1', function () {
      var result = undefined;
      var expectedPassword = '6';
      var url = 'foo';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();
      var statusCallbackCallCount = 0;

      beforeEach(function(done) {
        var statusCallback = function(percentage) {
          statusCallbackCallCount++;
        };
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };
        passwordLib.calculatePasswordSjclPbkdf2(password, url, { length: 1, verbose: true, statusCallback: statusCallback }).then(resultCallback);
      });

      it('should calculate password correclty', function () {
        expect(result).toBe(expectedPassword);
        
      });
    });

    describe('Tests for length 2', function () {
      var result = undefined;
      var expectedPassword = '6i';
      var url = 'foo';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();
      var statusCallbackCallCount = 0;

      beforeEach(function(done) {
        var statusCallback = function(percentage) {
          statusCallbackCallCount++;
        };
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };
        passwordLib.calculatePasswordSjclPbkdf2(password, url, { length: 2, verbose: true, statusCallback: statusCallback }).then(resultCallback);
      });

      it('should calculate password correclty', function () {
        expect(result).toBe(expectedPassword);
        
      });
    });

    describe('Tests for length 3', function () {
      var result = undefined;
      var expectedPassword = '6iF';
      var url = 'foo';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();
      var statusCallbackCallCount = 0;

      beforeEach(function(done) {
        var statusCallback = function(percentage) {
          statusCallbackCallCount++;
        };
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };
        passwordLib.calculatePasswordSjclPbkdf2(password, url, { length: 3, verbose: true, statusCallback: statusCallback }).then(resultCallback);
      });

      it('should calculate password correclty', function () {
        expect(result).toBe(expectedPassword);
        
      });
    });

    describe('Tests for default options with length of 4', function () {
      var result = undefined;
      var expectedPassword = '6iF\'';
      var url = 'foo';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();
      var statusCallbackCallCount = 0;

      beforeEach(function(done) {
        var statusCallback = function(percentage) {
          statusCallbackCallCount++;
        };
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };
        passwordLib.calculatePasswordSjclPbkdf2(password, url, { length: 4, verbose: true, statusCallback: statusCallback }).then(resultCallback);
      });

      it('should calculate password correclty', function () {
        expect(result).toBe(expectedPassword);
        
      });
    });

    describe('Tests for default options with length of 5', function () {
      var result = undefined;
      var expectedPassword = '6iF\'2';
      var url = 'foo';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();
      var statusCallbackCallCount = 0;

      beforeEach(function(done) {
        var statusCallback = function(percentage) {
          statusCallbackCallCount++;
        };
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };
        passwordLib.calculatePasswordSjclPbkdf2(password, url, { length: 5, verbose: true, statusCallback: statusCallback }).then(resultCallback);
      });

      it('should calculate password correclty', function () {
        expect(result).toBe(expectedPassword);
        
      });
    });

    describe('Tests for default options with length of 200', function () {
      var result = undefined;
      var expectedPassword = '6iF\'2X2UHvhwHMepdLq3n7lbP1SN7dZFsfdhOszKNX4zVAYOPpuE92x9Wu0MyTw7cJlkrIzrl5d62qIqlxe1Mg$%';
      var url = 'foo';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();
      var statusCallbackCallCount = 0;

      beforeEach(function(done) {
        var statusCallback = function(percentage) {
          statusCallbackCallCount++;
        };
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };
        passwordLib.calculatePasswordSjclPbkdf2(password, url, { length: 200, verbose: true, statusCallback: statusCallback }).then(resultCallback);
      });

      it('should calculate password correclty, with max length of 89', function () {
        expect(result).toBe(expectedPassword);
        
      });
    });

  });

  describe('Tests for password_lib.calculatePassword', function () {

    jasmine.DEFAULT_TIMEOUT_INTERVAL = 100000;

    describe('Tests for default options with proper url', function () {
      var result = undefined;
      var expectedPassword = 'mY6&oQmNSV1vdGZo3laj';
      var url = 'http://www.foo.com/abcd?xyz';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();
      var statusCallbackCallCount = 0;

      beforeEach(function(done) {
        var statusCallback = function(percentage) {
          statusCallbackCallCount++;
        };
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };
        passwordLib.calculatePassword(password, url, {verbose: true, statusCallback: statusCallback}).then(resultCallback);
      });

      it('should calculate password correctly', function () {
        expect(result).toBe(expectedPassword);
        expect(statusCallbackCallCount).not.toBeLessThan(1);
      });
    });

    describe('Tests for default options with proper url', function () {
      var result = undefined;
      var expectedPassword = 'mY6&oQmNSV1vdGZo3laj';
      var url = 'http://www.foo.com/abcd?xyz';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();

      beforeEach(function(done) {
        var statusCallback = function(percentage) {
          statusCallbackCallCount++;
        };
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };

        passwordLib.calculatePassword(password, url, { verbose: true }).then(resultCallback);
      });

      it('should calculate password correctly', function () {
        expect(result).toBe(expectedPassword);
      });
    });

    describe('Tests for default options with different subdomain', function () {
      var result = undefined;
      var expectedPassword = 'mY6&oQmNSV1vdGZo3laj';
      var url = 'http://abd.foo.com';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();
      var statusCallbackCallCount = 0;

      beforeEach(function(done) {
        var statusCallback = function(percentage) {
          statusCallbackCallCount++;
        };
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };
        passwordLib.calculatePassword(password, url, { verbose: true, statusCallback: statusCallback }).then(resultCallback);
      });

      it('should calculate password correctly', function () {
        expect(result).toBe(expectedPassword);
        expect(statusCallbackCallCount).not.toBeLessThan(1);
      });
    });

    describe('Tests for default options with different superdomain', function () {
      var result = undefined;
      var expectedPassword = 'mY6&oQmNSV1vdGZo3laj';
      var url = 'http://www.foo.ch';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();
      var statusCallbackCallCount = 0;

      beforeEach(function(done) {
        var statusCallback = function(percentage) {
          statusCallbackCallCount++;
        };
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };
        passwordLib.calculatePassword(password, url, { verbose: true, statusCallback: statusCallback }).then(resultCallback);
      });

      it('should calculate password correctly', function () {
        expect(result).toBe(expectedPassword);
        expect(statusCallbackCallCount).not.toBeLessThan(1);
      });
    });

    describe('Tests for default options with different domain', function () {
      var result = undefined;
      var expectedPassword = '7Ca^8BoNcDz1iZ7C9aBV';
      var url = 'http://www.foo2.com/abcd?xyz';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();
      var statusCallbackCallCount = 0;

      beforeEach(function(done) {
        var statusCallback = function(percentage) {
          statusCallbackCallCount++;
        };
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };
        passwordLib.calculatePassword(password, url, { verbose: true, statusCallback: statusCallback }).then(resultCallback);
      });

      it('should calculate password correctly', function () {
        expect(result).toBe(expectedPassword);
        expect(statusCallbackCallCount).not.toBeLessThan(1);
      });
    });

    describe('Tests for default options without small chars', function () {
      var result = undefined;
      var expectedPassword = 'Y6&QNSV1GZ3AL6URD162';
      var url = 'foo';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();
      var statusCallbackCallCount = 0;

      beforeEach(function(done) {
        var statusCallback = function(percentage) {
          statusCallbackCallCount++;
        };
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };
        passwordLib.calculatePassword(password, url, { smallLetters: false, verbose: true, statusCallback: statusCallback }).then(resultCallback);
      });

      it('should calculate password correclty', function () {
        expect(result).toBe(expectedPassword);
        expect(statusCallbackCallCount).not.toBeLessThan(1);
      });
    });

    describe('Tests for default options without capital chars', function () {
      var result = undefined;
      var expectedPassword = 'm6&om1vdo3laj6fda16v';
      var url = 'foo';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();
      var statusCallbackCallCount = 0;

      beforeEach(function(done) {
        var statusCallback = function(percentage) {
          statusCallbackCallCount++;
        };
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };
        passwordLib.calculatePassword(password, url, { capitalLetters: false, verbose: true, statusCallback: statusCallback }).then(resultCallback);
      });

      it('should calculate password correclty', function () {
        expect(result).toBe(expectedPassword);
        expect(statusCallbackCallCount).not.toBeLessThan(1);
      });
    });

    describe('Tests for default options without numbers', function () {
      var result = undefined;
      var expectedPassword = 'mY&oQmNSVvdGZolajALU';
      var url = 'foo';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();
      var statusCallbackCallCount = 0;

      beforeEach(function(done) {
        var statusCallback = function(percentage) {
          statusCallbackCallCount++;
        };
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };
        passwordLib.calculatePassword(password, url, { numbers: false, verbose: true, statusCallback: statusCallback }).then(resultCallback);
      });

      it('should calculate password correclty', function () {
        expect(result).toBe(expectedPassword);
        expect(statusCallbackCallCount).not.toBeLessThan(1);
      });
    });

    describe('Tests for default options without special chars', function () {
      var result = undefined;
      var expectedPassword = 'mY6oQmNSV1vdGZo3lajA';
      var url = 'foo';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();
      var statusCallbackCallCount = 0;

      beforeEach(function(done) {
        var statusCallback = function(percentage) {
          statusCallbackCallCount++;
        };
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };
        passwordLib.calculatePassword(password, url, { specialChars: false, verbose: true, statusCallback: statusCallback }).then(resultCallback);
      });

      it('should calculate password correclty', function () {
        expect(result).toBe(expectedPassword);
        expect(statusCallbackCallCount).not.toBeLessThan(1);
      });
    });

    describe('Tests for default options with explicit special chars', function () {
      var result = undefined;
      var expectedPassword = 'mY6.oQmNSV1vdGZo3laj';
      var url = 'foo';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();
      var statusCallbackCallCount = 0;

      beforeEach(function(done) {
        var statusCallback = function(percentage) {
          statusCallbackCallCount++;
        };
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };
        passwordLib.calculatePassword(password, url, { specialCharList: ';.', verbose: true, statusCallback: statusCallback }).then(resultCallback);
      });

      it('should calculate password correclty', function () {
        expect(result).toBe(expectedPassword);
        expect(statusCallbackCallCount).not.toBeLessThan(1);
      });
    });

    describe('Tests for length 0', function () {
      var result = undefined;
      var expectedPassword = '';
      var url = 'foo';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();
      var statusCallbackCallCount = 0;

      beforeEach(function(done) {
        var statusCallback = function(percentage) {
          statusCallbackCallCount++;
        };
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };
        passwordLib.calculatePassword(password, url, { length: 0, verbose: true, statusCallback: statusCallback }).then(resultCallback);
      });

      it('should calculate password correclty', function () {
        expect(result).toBe(expectedPassword);
        expect(statusCallbackCallCount).not.toBeLessThan(1);
      });
    });

    describe('Tests for length 1', function () {
      var result = undefined;
      var expectedPassword = 'm';
      var url = 'foo';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();
      var statusCallbackCallCount = 0;

      beforeEach(function(done) {
        var statusCallback = function(percentage) {
          statusCallbackCallCount++;
        };
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };
        passwordLib.calculatePassword(password, url, { length: 1, verbose: true, statusCallback: statusCallback }).then(resultCallback);
      });

      it('should calculate password correclty', function () {
        expect(result).toBe(expectedPassword);
        expect(statusCallbackCallCount).not.toBeLessThan(1);
      });
    });

    describe('Tests for length 2', function () {
      var result = undefined;
      var expectedPassword = 'mY';
      var url = 'foo';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();
      var statusCallbackCallCount = 0;

      beforeEach(function(done) {
        var statusCallback = function(percentage) {
          statusCallbackCallCount++;
        };
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };
        passwordLib.calculatePassword(password, url, { length: 2, verbose: true, statusCallback: statusCallback }).then(resultCallback);
      });

      it('should calculate password correclty', function () {
        expect(result).toBe(expectedPassword);
        expect(statusCallbackCallCount).not.toBeLessThan(1);
      });
    });

    describe('Tests for length 3', function () {
      var result = undefined;
      var expectedPassword = 'mY6';
      var url = 'foo';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();
      var statusCallbackCallCount = 0;

      beforeEach(function(done) {
        var statusCallback = function(percentage) {
          statusCallbackCallCount++;
        };
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };
        passwordLib.calculatePassword(password, url, { length: 3, verbose: true, statusCallback: statusCallback }).then(resultCallback);
      });

      it('should calculate password correclty', function () {
        expect(result).toBe(expectedPassword);
        expect(statusCallbackCallCount).not.toBeLessThan(1);
      });
    });

    describe('Tests for default options with length of 4', function () {
      var result = undefined;
      var expectedPassword = 'mY6&';
      var url = 'foo';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();
      var statusCallbackCallCount = 0;

      beforeEach(function(done) {
        var statusCallback = function(percentage) {
          statusCallbackCallCount++;
        };
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };
        passwordLib.calculatePassword(password, url, { length: 4, verbose: true, statusCallback: statusCallback }).then(resultCallback);
      });

      it('should calculate password correclty', function () {
        expect(result).toBe(expectedPassword);
        expect(statusCallbackCallCount).not.toBeLessThan(1);
      });
    });

    describe('Tests for default options with length of 5', function () {
      var result = undefined;
      var expectedPassword = 'mY6&o';
      var url = 'foo';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();
      var statusCallbackCallCount = 0;

      beforeEach(function(done) {
        var statusCallback = function(percentage) {
          statusCallbackCallCount++;
        };
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };
        passwordLib.calculatePassword(password, url, { length: 5, verbose: true, statusCallback: statusCallback }).then(resultCallback);
      });

      it('should calculate password correclty', function () {
        expect(result).toBe(expectedPassword);
        expect(statusCallbackCallCount).not.toBeLessThan(1);
      });
    });

    describe('Tests for default options with length of 200', function () {
      var result = undefined;
      var expectedPassword = 'mY6&oQmNSV1vdGZo3lajAL6URfDda16vi23v6Bk6SPZIVwhtnZTXfoTQ3hyvhaI99c0Ap0Styw7sdUy>NCvCLw1pe!@v63dCZRwARSlCVn9DvXqKPvZF6IjvzYRWe0kX3s9RWemiu]w?/S6CtIDCLQOiB)OKeXW"gnKxkAK89oI#';
      var url = 'foo';
      var password = 'bar';
      var defaultOptions = passwordLib.getDefaultOptions();
      var statusCallbackCallCount = 0;

      beforeEach(function(done) {
        var statusCallback = function(percentage) {
          statusCallbackCallCount++;
        };
        var resultCallback = function(generatedPassword) {
          result = generatedPassword;
          done();
        };
        passwordLib.calculatePassword(password, url, { length: 200, verbose: true, statusCallback: statusCallback }).then(resultCallback);
      });

      it('should calculate password correclty, with max length of 172', function () {
        expect(result).toBe(expectedPassword);
        expect(statusCallbackCallCount).not.toBeLessThan(1);
      });
    });

  });
})();
