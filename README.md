## Hmac_Sha1
Implementation of [HMAC algorithm](https://en.wikipedia.org/wiki/Hash-based_message_authentication_code#Implementation) in javascript, using [SHA1](https://en.wikipedia.org/wiki/SHA-1) as underline hash functon.

It is to be used where using of ArrayBuffer is not an option for what ever reason.
### Idea

It seems that sha1 functions by default return string of 40 hex chars that is just, well *hex string representation* of underlying data, not the data itself. Meaning if sha1 produces data stream of, for example:

`0100 1110` which if represent as hex string is "4e"

, it returns "4e". By default.

But we cant *directly* use that in our HMAC alghorithm since "4e" is *different* stream of data:

`0011  0110  0110 1001` its hex is "3465"

So we cant use different data then what sha1 has really produced, what we can do is this hex string representation ("4e") of underlying data convert to it's character counterpart:

`0100` `1110` <-- ("4e") becomes char ("N")--> `0100 1110`.

In this context it's good to think that sha1 spits out hex string by treating every 4 bits of underlying data, a *nibble*. And that we compress that string by mapping 8 bits of data to their string representation.

That is char "N" is *exact mapping* of data that sha1 produced it is not hex string representation of data. If we have 40 hex chars, that means 40 bytes and by [SHA1 rfc](https://tools.ietf.org/html/rfc2104), sha1 produces 20 byte data. By doing this conversion we get that 20 byte data and all the time we are using strings with same effect if we were using ArrayBuffer, at least that's the idea.

## Usage

I've done some code that uses method explained above. So it should work where you can't have access to `ArrayBufer`. 
It works only with plain javascript strings.

I'm using *Rusha.js* as sha1 function, all info you can find [here](https://github.com/srijs/rusha). You can use anything you want for sha1.  Also there are 3 functions, byteLength hexToString, and oneByteChar for operations that hmacSha1 uses.
#### Examples:
In this example the key and message (baseString) for testing are used from [twitter api example](https://dev.twitter.com/oauth/overview/creating-signatures).

```javascript
var baseStr = "POST&https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521"

var key = "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw&LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE";

hmacSha1 = new HmacSha1();

hmacSha1.digest(key, baseStr) //   b679c0af18f4e9c587ab8e200acd4e48a93f8cb6
```


[Wiki example](https://en.wikipedia.org/wiki/Hash-based_message_authentication_code#Examples):


```javascript
hmacSha1 = new HmacSha1();
hmacSha1.digest("key", "The quick brown fox jumps over the lazy dog") // de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9
```

##### Note:
If key or the massage contain backward slash the JS engine fill interpret it as a escape sequence character "\\", or in other words it will ignore it. So the funcion produces digest like there is no escape sequence character present, in both strings.


```javascript
hmacSha1 = new HmacSha1();
hmacSha1.digest("ke\y", "So\me mess\age") // b93ddca7f62b74ab43cb23e0581a05d50a27b9e9
// Result is like we passed "key" and "Some message"
```

So we need to escape each backward slash like so:


```javascript
hmacSha1 = new HmacSha1();
hmacSha1.digest("ke\\y", "So\\me mess\\age") // 136d22549e17ee6665dc398bbba43c5e912e3e92
// Result is like we passed "ke\y" and "So\me messs\age"
```
You can test keys and messages [here](https://jsfiddle.net/dzh5euo4/3/)(open console) in jsfiddle. 
And a [reference point](https://caligatio.github.io/jsSHA/) so you can see it complies with other implementations of HMAC_SHA1.

