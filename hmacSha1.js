var crypto;
var sha1;

try{
  crypto = require('crypto');
  
   sha1 = function(str, enc){
      hash = crypto.createHash('sha1');
      hash.update(str, enc)
      return  hash.digest('hex');
   }

}
catch(err){
   console.log('core crypto lib is unavalable: '+ err);
}


  function HmacSha1(){
     this.blocksize = 64; // 64 when using these hash functions: SHA-1, MD5, RIPEMD-128/160 .
    
     var opad = 0x5c; // outer padding  constant = (0x5c) . And 0x5c is just hexadecimal for backward slash "\" 
     var ipad = 0x36; // inner padding contant = (0x36). And 0x36 is hexadecimal for char "6".
                      // We made both constants private.
     
     this.digest =  function (key, baseString, enc){ // the actual digest function
      
       var opad_key = ""; // outer padded key
       var ipad_key = ""; // inner padded key
       var kLen = this.byteLength(key,enc); // length of key in bytes;
       var diff;
       var hashedKeyLen;

       if(kLen < this.blocksize){  
           diff = this.blocksize - kLen; // diff is how mush  blocksize is bigger then the key
           console.log('kLen: '+ kLen);
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
       
         var charCode;         // Code, numeric represantation of char 
        
         for(var j = 0; j < this.blocksize; j++){ 
               
             if(diff && (j+diff) >= this.blocksize || j >= hashedKeyLen){  // if diff exists (key is shorter then
                                                        // blocksize) and if we are at boundry where we should
                                                        // be, apply XOR on zero byte and constants, result put
                                                        // in corresponding padding key. Or the key was too long
                                                        // and was hashed, then also we need to do same thing.
                 o_zeroPaddedCode = 0x00 ^ opad;  // XOR the zero byte with outer padding constant 
                 opad_key += String.fromCharCode(o_zeroPaddedCode); // convert result back to string
                 
                 i_zeroPaddedCode = 0x00 ^ ipad;
                 ipad_key += String.fromCharCode(i_zeroPaddedCode);
              }
              else {
                 charCode = key.codePointAt(j);   // get code (number) of that char
                  
                 o_paddedCode =  charCode ^ opad; // XOR the char code with outer padding constant (opad)
                 opad_key += String.fromCharCode(o_paddedCode); // convert back code result to string
                  
                 i_paddedCode = charCode ^ ipad;  // XOR with the inner padding constant (ipad)
                 ipad_key += String.fromCharCode(i_paddedCode);
               
              }
            
  
              
          }
          console.log("opad_key: ", "|"+opad_key+"|",' len: '+ opad_key.length, "\nipad_key: ", "|"+ipad_key+"|", " len: "+ipad_key.length); // Prints opad and
                                                                                // ipad key, line can be deleted.
       }.bind(this))() // binding "this" reference in applyXor to each "instance" of HmacSha1  
          console.log("sha 1: ipad_key + baseString: |"+ (ipad_key + baseString));
          console.log("sha1: "+ sha1(ipad_key + baseString)); 
          console.log("sha1(with enc): "+ sha1(ipad_key + baseString, enc)); 
         return sha1(opad_key + this.hexToString(sha1(ipad_key + baseString, enc))) ;
      
     }
  }
  HmacSha1.prototype.messages = {
     nonAscii: 'Non ASCII code detected, function aborted'
  }
  
  HmacSha1.prototype.byteLength  = function (str, enc){ // If only 'str' is supplied function returns length 
                                                         // of str in bytes. If both arguments are there,
                                                         // function returns code (number) representation of
                                                         // character at index 'idx'.
     var bytes = 0, 
         len = str.length,
         i, 
         charCode;
         
     for (i = 0; i < len; i++){
           
         charCode = String.fromCharCode(str[i]); // take char code from i-th place 
         if(charCode <= 0xff){   // 1 byte
              bytes++;
              continue;
         }

         if(charCode <= 0xffff){ // 2
              bytes+=2; 
              continue;
         }
         
         if(charCode <=0xffffff){// 3
              bytes+=3;
               
         }
         else bytes+=4;          // 4
     }

     console.log('buffer length: ', Buffer.byteLength(str, enc));
     console.log('normal length: ', str.length) 
     console.log('mine: '+ bytes * 2);
     return Buffer.byteLength(str,enc);// bytes * 2 ; // and since javascript takes 2 bytes to store every character, we are multiplying by 2

    
    
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
           
            bin = shiftedL | rcode; // bitwise OR. This is essantialy concatenation. One character from two. 
            char = String.fromCodePoint(bin); // convert it back to string
            result += char;         // append to result string
     
            
    }
     
    return result;
  }

  module.exports = HmacSha1;  // returns function that can be used in constructor calls, with 'new'



