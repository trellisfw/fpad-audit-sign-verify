'use strict'
var sha256 = require('js-sha256');
var fs = require('fs');
var KJUR = require('jsrsasign');
const _ = require('lodash');
var Promsise = require('bluebird').Promise; 
var agent = require('superagent-promise')(require('superagent'), Promise);

module.exports = {
  generate: generate,
  verify: verify,
}

function contentModified(audit, sJWT) {
  // Decode the content and validate it against the content reconstructed with the public key.
  var decoded = KJUR.jws.JWS.readSafeJSONString(KJUR.b64utoutf8(sJWT.split(".")[1]));
  if (audit.signatures.length === 1) {
    delete audit.signatures;
  } else audit.signatures.pop();
  var reconstructedAudit = self.serialize(audit);
  reconstructedAudit = sha256(reconstructedAudit);
  if (decoded.hash === reconstructedAudit) return true;
  return false;
}

function isValid(sJWT, header) {
  var pubKey = KJUR.KEYUTIL.getKey(header.jwk);
//TODO: I don't understand why KJUR wants alg to be an array, but generating the JWT with alg as an array fails. Perhaps I wasn't generating it correctly
  if (header.alg) header.alg = [header.alg]
  if (header.typ) header.typ = [header.typ]
  if (header.iss) header.iss = [header.iss]
  if (header.sub) header.sub = [header.sub]
  if (header.aud) header.aud = [header.aud]
  return KJUR.jws.JWS.verifyJWT(sJWT, pubKey, header); // Verify the JWT
}


function verify(audit, publicKey, signedAudit) {
  agent('GET', 'https://raw.githubusercontent.com/fpad/trusted-list/master/keys.json')
  .end()
  .then(function onResult(res) {
    var trusted = JSON.parse(res.text);
    var sJWT = audit.signatures[audit.signatures.length-1]
    var header = KJUR.jws.JWS.readSafeJSONString(KJUR.b64utoutf8(sJWT.split(".")[0]));
    // Handle JWK
    if (header.jwk) {
      if (!header.jwk.n) throw 'JWK missing hash' ; // For some reason, no hash of the key was included. Can't check. Don't trust!
      if (!trusted[header.jwk.n]) throw 'Signer JWK not on trusted list'; // Its not on the trusted list. Don't trust!
      if (!isValid(sJWT, header)) throw 'JWT invalid';
      if (contentModified(audit)) throw 'Audit modified';
      return true
    // Handle embedded JKU
    } else if (header.jku && header.kid) {
      if (!trusted[header.jku]) return false; // Its not on the trusted list. Don't trust!
      agent('GET', header.jku) //Get the JWK from the JKU and verify the JWT
      .end()
      .then(function onResult(jkuRes) {   
        var keySet = JSON.parse(jkuRes.text);
        console.log(keySet);
        console.log(header);
        var jwk;
        keySet.keys.forEach((key) => {
          if (key.kid === header.kid) {
            jwk = key
          }
        })
        if (!jwk) throw 'Signer JWK not on trusted list';
        if (!isValid(sJWT, header)) throw 'JWT invalid';
        if (contentModified(audit)) throw 'Audit modified';
        return true
      }, function onError(err) {
      });
    }
  }, function onError(err) {
  });
}

function generate(inputAudit, kid, alg, kty, typ, jwk, jku) {
  var data = inputAudit;                                                         
  if (serialize) var data = serialize(data);                                                  
  data = sha256(data);                                                           
  data = { hash: data };                                                         
// Create the JWE JOSE Header                                                    
  var oHeader = {                                                                
    alg: alg,                                                                    
    typ: typ,                                                                
    kid: kid,                                                     
    iat: Math.floor(Date.now() / 1000),                                          
    kty: kty,                                                                    
  };                                                                             
  if (jwk) {
    oHeader.jwk = jwk;
  } else if (jku) {
    oHeader.jku = jku;
  }
  var prvKey = KJUR.KEYUTIL.getKey(jwk)                               
  var assertion = KJUR.jws.JWS.sign(alg, JSON.stringify(oHeader), data, prvKey); 

  if (inputAudit.signatures) {                                                   
    inputAudit.signatures.push(assertion);                                       
  } else {                                                                       
    inputAudit.signatures = [assertion];                                         
  }                                                                              
  
  return inputAudit;
}

function serialize(obj) {

  if (typeof obj === 'number') throw new Error('You cannot serialize a number with a hashing function and expect it to work.  Use a string.');
  if (typeof obj === 'string') return '"'+obj+'"';
  if (typeof obj === 'boolean') return (obj ? 'true' : 'false');
  // Must be an array or object
  var isarray = _.isArray(obj);
  var starttoken = isarray ? '[' : '{';
  var   endtoken = isarray ? ']' : '}';

  if (!obj) return 'null';

  const keys = _.keys(obj).sort(); // you can't have two identical keys, so you don't have to worry about that.

  return starttoken
    + _.reduce(keys, (acc,k,index) => {
      if (!isarray) acc += '"'+k+'":'; // if an object, put the key name here
      acc += serialize(obj[k]);
      if (index < keys.length-1) acc += ',';
      return acc;
    },"")
    + endtoken;
}
