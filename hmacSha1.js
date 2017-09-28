var crypto;
var sha1;

try{
  crypto = require('crypto');
  
   sha1 = function(key,enc, format){
      enc =  enc || 'binary';               // Fix for node versions >=6.0.0, in which default encoding is 
                                            // changed to utf-8.
      format = format || 'hex';             // Defaults to hex
      var hash = crypto.createHash('sha1'); // Create instance of sha1
      hash.update(key, enc);                // Feed data to it, specify encoding
      return  hash.digest(format);          // Return result specified format
   }

}
catch(err){
   console.log('core crypto lib is unavalable: '+ err);
}


  function HmacSha1(format){ // Format of hmac result (defaults to 'hex', can be 'base64')
     this.blocksize = 64;    // 64 when using these hash functions: SHA-1, MD5, RIPEMD-128/160 .
    
     var opad = 0x5c; // outer padding  constant = (0x5c) . And 0x5c is just hexadecimal for backward slash "\" 
     var ipad = 0x36; // inner padding contant = (0x36). And 0x36 is hexadecimal for char "6".
                      // We made both constants private.
     
     this.digest =  function (key, baseString, enc){ // the actual digest function

       var opad_key = ""; // outer padded key
       var ipad_key = ""; // inner padded key

       var kLen = (enc === 'latin-1' || enc === 'utf8') ? this.asciiOnly(key) : key.length; // Enforce ascii in
                                                                                     // key, only  if non ascii 
                                                                                     // encoding specified.
       var diff;         
       var hashedKeyLen;

       if(kLen < this.blocksize){  
           diff = this.blocksize - kLen;          // diff is how much blocksize is bigger then the key
       }
      
       if(kLen > this.blocksize){ 
          key = this.hexToString(sha1(key, enc)); // The hash of 40 hex chars(40bytes) convert to exact char 
                                                  // mappings, each char has codepoint from 0x00 to 0xff.
                                                  // Produces string of 20 bytes.
          hashedKeyLen =  key.length;             // Take the length of key
       }
      
    
       (function applyXor(){   // Reads one char, at the time, from key and applies XOR constants on it
                               // acording to the length of the key.
         var o_zeroPaddedCode; // result from opading the zero byte
         var i_zeroPaddedCode; // res from ipading the zero byte
         var o_paddedCode;     // res from opading the char from key
         var i_paddedCode;     // res from ipading the char from key
         var code;             //  Numeric represantation of char 
        
         for(var j = 0; j < this.blocksize; j++){ 
               
             if(diff && (j+diff) >= this.blocksize || j >= hashedKeyLen){  // if diff exists (key is shorter then
                                                        // blocksize) and if we are at boundry where we should
                                                        // be, apply XOR on zero byte and constants, result put
                                                        // in corresponding padding key. Or the key was too long
                                                        // and was hashed, then also we need to do same thing.
                 o_zeroPaddedCode = 0x00 ^ opad;  // XOR the zero byte with outer padding constant 
                 opad_key += String.fromCodePoint(o_zeroPaddedCode); // convert result back to string
                                                                     // using ".fromCodePoint()" so it can 
                                                                     // correctly return codes from chars in 
                                                                     // higher unicode plains
                 i_zeroPaddedCode = 0x00 ^ ipad;
                 ipad_key += String.fromCodePoint(i_zeroPaddedCode);
              }
              else {
                 code = key.codePointAt(j);   // get code (number) of that char
                  
                 o_paddedCode =  code ^ opad; // XOR the char code with outer padding constant (opad)
                 opad_key += String.fromCodePoint(o_paddedCode); // convert back code result to string
                  
                 i_paddedCode = code ^ ipad;  // XOR with the inner padding constant (ipad)
                 ipad_key += String.fromCodePoint(i_paddedCode);
               
              }
          }
         // console.log("opad_key: ", "|"+opad_key+"|",' len: '+ opad_key.length, "\nipad_key: ", "|"+ipad_key+"|", " len: "+ipad_key.length); // Prints opad and  ipad key, line can be deleted.
       }.bind(this))() // binding "this" reference in applyXor to each "instance" of HmacSha1  
        
       var stringify = this.hexToString(sha1(ipad_key + baseString, enc));// convert sha1 hex to character string 
       if(format === 'base64') return sha1(opad_key + stringify, '', format); // pass format as third arg
       else return sha1(opad_key + stringify); 
     }
  }

  HmacSha1.prototype.messages = {
     nonAscii: 'Key must contain only ascii code.'
  }
  
  HmacSha1.prototype.asciiOnly  = function (str){ // Checks for ascii code, if ok, returns number of characters
                                                  // in str  
     var len = str.length,
         code,
         i;
     for(i = 0; i < len; i++){
       
         code = str.codePointAt(i);
         if(code > 0x7f){                         // check non ascii code
           throw new Error(this.messages.nonAscii +" Char outside range is: " + String.fromCodePoint(code))
           return;
         }
    
     }
     
     return len;  // if all ok, return length (number of chars);
  }
    
  HmacSha1.prototype.hexToString = function (sha1Output){ // Converts every pair of hex CHARS to their character
                                                          // conterparts.
                                                          // example1: "4e" is converted to char "N" 
                                                          // example2: "34" is converted to char "4"
      
    var l;        // char at "i" place, left
    var lcode;    // code parsed from left char
    var shiftedL; // left character shifted to the left 
      
    var r;        // char at "i+1" place, right
    var rcode;    // code parsed from right char
    
    var bin;      // code from bitwise OR operation
    var char;     // one character
    var result = ""; // result string 
      
   for (var i = 0; i < sha1Output.length; i+=2){ // In steps by 2
           l = sha1Output[i];                    // Take "left" char
           
           if(typeof l === "number") lcode = parseInt(l);         // Parse the number
           else if(typeof l === "string") lcode = parseInt(l,16); // Take the code if char is hex number
                                                                  // in range  (a...f);
           
            shiftedL = lcode << 4 ; // Shift it to left 4 places, gets filled in with 4 zeroes from the right
            r = sha1Output[i+1];    // Take next char
           
           if(typeof r === "number") rcode = parseInt(r);         // Parse the number
           else if(typeof r === "string") rcode = parseInt(r,16); // Take the code
           
            bin = shiftedL | rcode; // Bitwise OR. This is essantialy concatenation. One character from two. 
            char = String.fromCodePoint(bin); // convert it back to string
            result += char;         // append to result string
     
            
    }
     
    return result;
  }

  module.exports = HmacSha1;  // returns function that can be used in constructor calls, with 'new'



