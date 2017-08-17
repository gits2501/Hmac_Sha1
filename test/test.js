var test = require('tap').test;
var HmacSha1 = require('../hmacSha1');

var hmac = new HmacSha1();

var key;
var baseStr;
var result;

test('digest', function(t){


  key = 'key';
  baseStr = 'The quick brown fox jumps over the lazy dog'
  result = hmac.digest(key, baseStr);

  t.equal(result, 'de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9','Should be  equal to "de7c9...b4d9" ');

  key = 'kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw&LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE';
  baseStr = 'POST&https%3A%2F%2Fapi.twitter.com%2F1.1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521';
  result = hmac.digest(key, baseStr);

  t.equal(result, '842b5299887e88760212a056ac4ec2ee1626b549','Should be  equal to "842b...b549"');

  key = 'The k\\e\\y'; // note that this is interpreted as 'The k\e\y'. Since it works with strings,
                       // watch out for escape sequence.
  baseStr = 'When deeds speak, words are nothing.';
  result = hmac.digest(key, baseStr)

  t.equal(result, 'f6fceaeacea4dd904122d08d79298937e2e077b3','Should be  equal to "f6fce...77b3"');

  key = "The k*e*y";
  baseStr = "He that breaks a thing to find out what it is has left the path of wisdom."
  result = hmac.digest(key, baseStr);
  
  t.equal(result, '38e70f00ea9083c3034457ec0e0481d13080518a','Should be  equal to "38e7...518a"');
  
t.end();
});

var str;
var pos;
var func;

test('oneByteChar',function(t){

   str = "Greek letter Phi Φ";
   pos = str.length -1;
   func = hmac.oneByteChar.bind(hmac, [str,pos]);
  
   t.throws(func ,hmac.messages.nonAscii, 'Should throw new Error with informative message');

   str =  "He who breaks a thing to find out what it is has left the path of wisdom";
   
   t.equals(hmac.oneByteChar(str), str.length, 'Should return byte length of ['+str.length+']');
   t.end(); 
});


test('hexToString', function(t){
   str = "34"
   t.equals(hmac.hexToString(str), '4', 'Should return 4');
   
   str = "4e"
   t.equals(hmac.hexToString(str), 'N', 'Should return N');
  
   str = "4e7057f9";
   t.equals(hmac.hexToString(str), 'NpWù', 'Should return NpWù');
   t.end()
   
});
