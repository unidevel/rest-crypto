'use strict';
const isBrowser=new Function("try {return this===window;}catch(e){ return false;}");
const ALGORITHM = 'aes-256-cbc';
var mod = {};
const OUTENC = 'hex';
if (isBrowser()) {
  var CryptoJS = require('crypto-js');
  var AES = require('crypto-js/aes');
  var Hex = CryptoJS.enc.Hex;
  var Utf8 = CryptoJS.enc.Utf8;
  var Base64 = CryptoJS.enc.Base64;
  var WordArray = CryptoJS.lib.WordArray;
  var CipherParams = CryptoJS.lib.CipherParams;
  var formatter = CryptoJS.format.OpenSSL;
  if ( OUTENC == 'hex' ) {
    formatter = CryptoJS.format.Hex;
  }
  mod = {
    md5: function(data, salt){
      return CryptoJS.HmacMD5(data.toString(), salt || '').toString();
    },
    randomStr: function(len, enc){
      var encoder = Hex;
      if ( enc == 'utf8' ) encoder = Utf8;
      else if ( enc == 'base64') encoder = Base64;
      return WordArray.random(len).toString(encoder);
    },
    encrypt: function(data, key, iv){
      var options = {mode: CryptoJS.mode.CBC, format: formatter};
      if ( iv ) options.iv = Hex.parse(iv);
      var encryptData = CryptoJS.AES.encrypt(data, Utf8.parse(key), options);
      return encryptData.toString();
    },
    decrypt: function(data, key, iv){
      var options = {mode: CryptoJS.mode.CBC, format: formatter};
      options.iv = Hex.parse(iv);
      var bytes = AES.decrypt(data, Utf8.parse(key), options);
      var text = bytes.toString(CryptoJS.enc.Utf8);
      return text;
    }
  }
}
else {
  var crypto = require('crypto');
  mod = {
    md5: function(data, salt){
      return crypto.createHmac('md5', salt || '').update(data.toString()).digest('hex');
    },
    randomStr(len, enc){
      return crypto.randomBytes(len).toString(enc || 'hex');
    },
    encrypt: function(data, key, iv){
      var cipher;
      if ( iv ) cipher = crypto.createCipheriv(ALGORITHM, key, new Buffer(iv, 'hex'));
      else cipher = crypto.createCipher(ALGORITHM, key);
      var data = cipher.update(data, 'utf8', OUTENC);
      data += cipher.final(OUTENC);
      return data;
    },
    decrypt: function(data, key, iv){
      var decipher;
      if ( iv ) decipher = crypto.createDecipheriv(ALGORITHM, key, new Buffer(iv, 'hex'));
      else decipher = crypto.createDecipher(ALGORITHM, key);
      var data = decipher.update(data, OUTENC, 'utf8');
      data += decipher.final('utf8');
      return data;
    }
  }
}

module.exports = mod;
