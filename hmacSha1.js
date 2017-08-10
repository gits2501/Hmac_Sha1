var crypto;
var sha1;

try{
  crypto = require('crypto');
  
   sha1 = function(str){
      hash = crypto.createHash('sha1');
      hash.update(str)
      return  hash.digest('hex');
   }

}
catch(err){
   console.log('crypto is unavalable: '+ err);

   sha1 = require('rusha.js'); 
   sha1 = sha1.digest; 
}


  

//var sha = new Rusha();   // this is where we make an "instance" of sha1 function
                           // You can use whatever library you choose for sha1,
                           // here we used Rusha.js
//var sha1 = sha.digest;   
  
  function HmacSha1(){
     this.blocksize = 64; // 64 when using these hash functions: SHA-1, MD5, RIPEMD-128/160 .
    
     var opad = 0x5c; // outer padding  constant = (0x5c) . And 0x5c is just hexadecimal for backward slash "\" 
     var ipad = 0x36; // inner padding contant = (0x36). And 0x36 is hexadecimal for char "6".
                      // We made both constants private.
     
     this.digest =  function (key, baseString){ // the actual hmac_sha1 function
      
       var opad_key = ""; // outer padded key
       var ipad_key = ""; // inner padded key
       var kLen = this.byteLength(key); // length of key in bytes;
     
       if(kLen < this.blocksize){  
          var diff = this.blocksize - kLen; // diff is how mush  blocksize is bigger then the key
       }
      
       if(kLen > this.blocksize){ 
          key = this.hexToString(sha1(key)); // The hash of 40 hex chars(40bytes) convert to exact char mappings,
                                           // each char has codepoint from 0x00 to 0xff.Produces string of 20 bytes.
         
          var hashedKeyLen =  this.byteLength(key); // take the length of key
       }
      
    
       (function applyXor(){   // Reads one char, at the time, from key and applies XOR constants on it
                               // acording to the byteLength of the key.
         var o_zeroPaddedCode; // result from opading the zero byte
         var i_zeroPaddedCode; // res from ipading the zero byte
         var o_paddedCode;     // res from opading the char from key
         var i_paddedCode;     // res from ipading the char from key
       
         var char;     // Plaseholder for one char from key 
         var charCode; // Code, numeric represantation of char 
        
         for(var j = 0; j < this.blocksize; j++){ 
               
             if(diff && (j+diff) >= this.blocksize || j >= hashedKeyLen){  // if diff exists (key is shorter then
                                                        // blocksize) and if we are at boundry where we should
                                                        // be, apply XOR on zero byte and constants, result put
                                                        // in corresponding padding key. Or the key was too long
                                                        // and was hashed, then also we need to do same thing.
                o_zeroPaddedCode = 0x00 ^ opad;  //XOR the zero byte with outer padding constant 
                opad_key += String.fromCharCode(o_zeroPaddedCode); // convert result back to string
                 
                i_zeroPaddedCode = 0x00 ^ ipad;
                ipad_key += String.fromCharCode(i_zeroPaddedCode);
              }
              else {
                char = this.oneByteCharAt(key,j);     // take char from key, only one byte char
                 charCode = char.codePointAt(0); // convert that char to number
                  
                 o_paddedCode =  charCode ^ opad; // XOR the char code with outer padding constant (opad)
                 opad_key += String.fromCharCode(o_paddedCode); // convert back code result to string
                  
                 i_paddedCode = charCode ^ ipad;  // XOR with the inner padding constant (ipad)
                 ipad_key += String.fromCharCode(i_paddedCode);
               
              }
            
  
              
          }
       //   console.log("opad_key: ", "|"+opad_key+"|", "\nipad_key: ", "|"+ipad_key+"|"); // Prints opad and
                                                                                // ipad key, line can be deleted.
       }.bind(this))() // binding "this" reference in applyXor to each "instance" of HmacSha1  
   
         return sha1(opad_key + this.hexToString(sha1(ipad_key + baseString))) ;
      
     }
  }
  HmacSha1.prototype.messages = {
     moreThenOne: 'More then 1 byte character detected, function aborted',
  }
  
  HmacSha1.prototype.byteLength  = function (str){  // Counts characters only 1byte in length, of a string.
                                                    // Very similar to oneByteChar().
                                                    // For clarity 2 funtions are made.
      var len = str.length;
      var i = 0;
      var byteLen = 0; // string byte lenght
      
      for (i; i < len; i++){
        var code = str.charCodeAt(i);              // Take single character from string
        if(code >= 0x0 && code <= 0xff) byteLen++; // Check that it is only 1byte in length and increase counter
        else{
           throw new Error(this.messages.moreThenOne);
           return;
        }
        
      }
      
      return byteLen;
    
  }
  
  HmacSha1.prototype.oneByteCharAt = function (str,idx){
       var code = str.codePointAt(idx);
       if(code >= 0x00 && code <= 0xff){ // we are interested at reading only one byte
          return str.charAt(idx); // return char.
       }    
       else{ 
          throw new Error(this.messages.moreThenOne)
       }
    
  };
  
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
      
   for (var i = 0; i < sha1Output.length; i+=2){ // in steps by 2
           l = sha1Output[i]; // take "left" char
           
           if(typeof l === "number") lcode = parseInt(l); // parse the number
           else if(typeof l === "string") lcode = parseInt(l,16); // take the code if char letter is hex number
                                                                  // in set (a...f)
           
            shiftedL = lcode << 4 ; // shift it to left 4 places, gets filled in with 4 zeroes from the right
            r = sha1Output[i+1];    // take next char
           
           if(typeof r === "number") rcode = parseInt(r); // parse the number
           else if(typeof r === "string") rcode = parseInt(r,16); 
           
            bin = shiftedL | rcode; // 
            char = String.fromCharCode(bin);
            result += char;
     
            
    }
    // console.log("|"+result+"|", result.length); // prints info, line can be deleted
     
    return result;
  }

  module.exports = HmacSha1;  // returns function that can be used in constructor calls, with 'new'



