'use strict';
const util = require('./util');
//const LZString = require('lz-string');
function encrypt(data, key, token, time){
  var md5 = util.md5(time, token);
  var data = util.encrypt(data, key, md5);
  //return LZString.compress(data);
  return data;
}

function decrypt(data, key, token, time){
  //var body = LZString.decompress(data);
  var body = data;
  var md5 = util.md5(time, token);
  return util.decrypt(body, key, md5);
}

class Multi {
  constructor(privateKey, token, trace){
    this.token = token;
    this.privateKey = privateKey;
    this.trace = trace;
    this.msg = {
      time: new Date().getTime(),
      data: []
    }
    if ( token ) this.msg.token = token;
    if ( trace ) this.msg.trace = trace;
  }

  encode(msg){
    var item = {};
    for ( var key in msg ){
      item[key] = msg[key];
    }
    this.msg.data.push(item);
    return this;
  }

  done(){
    if ( this.token ){
      this.msg.data = encrypt(JSON.stringify(this.msg.data), this.privateKey, this.token, this.msg.time);
    }
    return this.msg;
  }
}

class Protocol {
  constructor(privateKey, token){
    if ( !privateKey || privateKey.length != 32) throw new Error('Invalid key length, must be 32 bytes!');
    this.privateKey = privateKey;
    if ( token ) this.token = token;
  }

  encode(msg){
    msg.time = new Date().getTime();
    if ( !msg.token && this.token ) msg.token = this.token;
    if ( msg.token ) {
      msg.data = encrypt(JSON.stringify(msg.data), this.privateKey, msg.token, msg.time);
    }
    return msg;
  }

  decode(msg){
    if ( !msg.token ) {
      return msg;
    }
    var data = decrypt(msg.data, this.privateKey, msg.token, msg.time);
    msg.data = JSON.parse(data);
    return msg;
  }

  multi(token){
    return new Multi(this.privateKey, token || this.token);
  }
}

function createProtocol(key, token){
  var privateKey = util.md5(key, token);
  return new Protocol(privateKey, token);
}

module.exports = createProtocol;
