## Hmac_Sha1        [![Build Status](https://travis-ci.org/gits2501/Hmac_Sha1.svg?branch=master)](https://travis-ci.org/gits2501/Hmac_Sha1)


In order to utilise many free APIs, communication with server needs authentication checks for the application that access it and for user in which name application makes the request. Lot's of API's still require [OAuth 1.0a](https://oauth.net/core/1.0a/#anchor15), where [HMAC_SHA1](https://en.wikipedia.org/wiki/Hash-based_message_authentication_code#Implementation) is significant part, for that purpose. 

This implementation uses only plain javascript strings so that is what it expects to pass it. Although sha1 function from nodes core crypto lib which this implementation depends uppon does use Buffers.
 Also, this hmac uses *ES6* `String.fromCodePoint(..)` to correctly map code points of higher unicode plains. 

### Idea

It seems that sha1 functions by default return string of 40 hex chars that is just, well *hex string representation* of underlying data, not the data itself. Meaning if sha1 produces data stream of, for example:

`0100 1110` which if represent as hex string is "4e"

, it returns "4e". By default.

But we cant *directly* use that in our HMAC alghorithm since "4e" is *different* stream of data:

`0011  0110  0110 1001` its hex is "3465"

So we cant use different data then what sha1 has really produced, what we can do is this hex string representation ("4e") of underlying data convert to it's character counterpart:

`0100` `1110` <-- ("4e") becomes char ("N")--> `0100 1110`.

In this context it's good to think that sha1 spits out hex string by treating every 4 bits of underlying data, a *nibble*. And that we compress that string by mapping 8 bits of data to their string representation.

That is char "N" is *exact mapping* of data that sha1 produced it is not hex string representation of data. If we have 40 hex chars that means 40 bytes and by [SHA1 rfc](https://tools.ietf.org/html/rfc2104), sha1 produces 20 byte data. By doing this conversion we get that 20 byte data and all the time we are using strings with same effect if we were using ArrayBuffer/Buffer, at least that's the idea
## Installation
#### node.js
`npm install hmac_sha1`

## Usage

The `digest` function of an Hmac_Sha1 instance receives three arguments, `key` , `baseString` and optional `enc`-oding.

### Examples:
In this example the key and message (baseString) for testing are used from [twitter api example](https://dev.twitter.com/oauth/overview/creating-signatures).

```javascript
var baseStr = "POST&https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521"

var key = "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw&LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE";

hmacSha1 = new HmacSha1();

hmacSha1.digest(key, baseStr) //   b679c0af18f4e9c587ab8e200acd4e48a93f8cb6
```

#### Normal
[Wiki example](https://en.wikipedia.org/wiki/Hash-based_message_authentication_code#Examples):

In most cases you are good with default usage:
```javascript
hmacSha1 = new HmacSha1(); // no result encoding specified, defaults to 'hex'
hmacSha1.digest("key", "The quick brown fox jumps over the lazy dog") // de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9
```
#### base64
If you want result in base64:
```javascript
hmacSha1 = new HmacSha1('base64'); // put format in constructor call
hmacSha1.digest("key", "The quick brown fox jumps over the lazy dog"); // 3nybhbi3iqa8ino29wqQcBydtNk=
```
#### utf8
You can use 'utf8' encoding:
```javascript
hmacSha1 = new HmacSha1('base64');
hmacSha1.digest('key', 'The quick brown fox jumps over the lazy dog¶汉字💩', 'utf8'); // LYsDRV73mlS0VAkq5WSr915Nnu4=                                                                            
```
##### Caviat
But, when you are using 'utf8' encoding your `key` must be in ascii code. Basicaly it means that only your baseString (message) is allowed to have non ascii chars. If that's not the case function throws an error:
```javascript
hmacSha1 = new HmacSha1('base64');
hmac.digest('key¶汉字','The quick brown fox jumps over the lazy dog¶汉字💩', 'utf8' ) // Error 

hmac.digest('key','The quick brown fox jumps over the lazy dog¶汉字💩', 'utf8' ) // LYsDRV73mlS0VAkq5WSr915Nnu4=

```
##### Note:
If *key* or the *massage* contain backward slash the JS engine will interpret it as a escape sequence character "\\", or in other words it will ignore it (depending of what subsequent char is). So the funcion produces digest like there is no escape sequence character present.


```javascript
hmacSha1 = new HmacSha1();
hmacSha1.digest("ke\y", "So\me mess\age") // b93ddca7f62b74ab43cb23e0581a05d50a27b9e9
// Result is like we passed "key" and "Some message"
```

So we need to escape each backward slash like so:


```javascript
hmacSha1 = new HmacSha1();
hmacSha1.digest("ke\\y", "So\\me mess\\age") // 136d22549e17ee6665dc398bbba43c5e912e3e92
// Result is like we passed "ke\y" and "So\me mess\age"
```
A [reference point](https://caligatio.github.io/jsSHA/) so you can see it complies with other implementations of HMAC_SHA1. Or fire up [HMAC](https://nodejs.org/api/crypto.html#crypto_class_hmac) from node's crypto lib.


Don't feel obliged to donate but any donation is greatly appreciated.

 [![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.me/gits2501pp)

Don't feel obliged to donate but any donation is greatly appreciated.
 [![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.me/gits2501pp)

