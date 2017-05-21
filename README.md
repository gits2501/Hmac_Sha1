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

### Implementation

I've done some code that uses method explained above. So it should work where you can't have access to `ArrayBufer`. 
It works only with plain javascript strings.

I'm using Rusha.js as sha1 function, all info you can find here. You can use anything. 
Can't include it here since post body is limited to 30000 chars. It's all in jsfiddle link bellow code. There the key and message(baseString) for testing are used from twitter api example. Also there are 3 functions, byteLength hexToString, and oneByteChar for operations that hmacSha1 uses. 
