'use strict'
var sha256 = require('js-sha256');
var fs = require('fs');
var KJUR = require('jsrsasign');
const _ = require('lodash');
var Promise = require('bluebird').Promise; 
var agent = require('superagent-promise')(require('superagent'), Promise);

module.exports = {
  generate: generate,
  verify: verify,
}

//This function compares the hash given in the most recent signature's JWT payload to a
//reconstructed hash of the audit. This most recent signature (and also the signatures
//key if only one signature was present) should be omitted in the computation of the hash.
//If the hashes match, we can conclude that data hasn't been modified.
function _isContentModified(audit) {
  if (!audit.signatures) return false
  if (audit.signatures.length === 0) return false
  var sJWT = audit.signatures[audit.signatures.length-1]
  // Decode the content and validate it against the content reconstructed with the public key.
  var decoded = KJUR.jws.JWS.readSafeJSONString(KJUR.b64utoutf8(sJWT.split(".")[1]));
  if (audit.signatures.length === 1) {
    delete audit.signatures;
  } else audit.signatures.pop();
  var reconstructedAudit = _serialize(audit);
  reconstructedAudit = sha256(reconstructedAudit);
  if (decoded.hash === reconstructedAudit) return false
  return true
}

// This function reconstructs the headers for verification using KJUR. KJUR wants alg to be
// an array for some reason even though generating the JWT with alg as an array does not work. 
function _isVerified(sJWT, header, jwk) {
  var pubKey = KJUR.KEYUTIL.getKey(jwk);
  if (header.alg) header.alg = [header.alg]
  if (header.typ) header.typ = [header.typ]
  if (header.iss) header.iss = [header.iss]
  if (header.sub) header.sub = [header.sub]
  if (header.aud) header.aud = [header.aud]
  if (header.kty) header.kty = [header.kty]
  return KJUR.jws.JWS.verifyJWT(sJWT, pubKey, header);
}

// This function verifies the given audit. The audit should contain the public key source
// necessary to verify itself (either JWK or JKU).
function verify(audit) {
  if (!audit.signatures) throw 'Audit has no signatures to be verified.'
  if (audit.signatures.length ===0) throw 'Audit has no signatures.'
  return agent('GET', 'https://raw.githubusercontent.com/fpad/trusted-list/master/keys.json')
  .end()
  .then(function onResult(res) {
    var trustedList = JSON.parse(res.text);
    var sJWT = audit.signatures[audit.signatures.length-1]
    var header = KJUR.jws.JWS.readSafeJSONString(KJUR.b64utoutf8(sJWT.split(".")[0]));
    if (!header) throw  'Malformed signature (JWT headers couldn\'t be parsed).';
    // Handle JWK
    if (header.jwk) {
      if (!header.jwk.n) throw 'Signature JWK was missing its hash.' ; // For some reason, no hash of the key was included. Can't check. Don't trust!
      if (!_isVerified(sJWT, header, header.jwk)) throw 'Audit signature is invalid.';
      if (!trustedList[header.jwk.n]) throw 'Audit signature is valid. The signer is not on the trusted list.'; // Its not on the trusted list. Don't trust!
      if (_isContentModified(audit)) throw 'Audit signature is valid. Signer is trusted. The Audit contents have been modified.';
      return true
    // Handle embedded JKU
    } else if (header.jku && header.kid) {
      return agent('GET', header.jku) //Get the JWK from the JKU and verify the JWT
      .end()
      .then(function onResult(jkuRes) {   
        var keySet = JSON.parse(jkuRes.text);
        var jwk;
        keySet.keys.forEach(function(key) {
          if (key.kid === header.kid) {
            jwk = key
          }
        })
        if (!jwk) throw 'Could not find the specified key at the given URL.';
        if (!_isVerified(sJWT, header, jwk)) throw 'Audit signature cannot be verified.';
        if (!trustedList[header.jku]) throw 'Audit signature is valid, but the signer is not on the trusted list.'; // Its not on the trusted list. Don't trust!
        if (_isContentModified(audit)) throw 'Audit signature is valid. Signer is trusted. The Audit contents have been modified.';
        return true;
      }, function onError(err) {
        throw err;
      });
    } else throw 'Audit headers are missing a public key source (either JWK or JKU) necessary for verification.'
  }, function onError(error) {
    throw error;
  });
}

//This function accepts an input audit along with the JWT headers necessary to 
//construct a JWT and appends an additional signature to the signatures key of 
//the audit.
function generate(inputAudit, prvJwk, headers) {
  if (!prvJwk) throw 'Private key required to sign the audit.';
  var data = _serialize(inputAudit);
  if (!data) throw 'An error occurred while trying to serialize the audit.'
  data = {hash: sha256(data)};
  if (!data) throw 'An error occurred while hashing the audit.'

  if (!headers.jwk && !headers.jku) throw 'Either a public JWK key or a JKU must be included for downstream verification of the given private key.' 
  if (headers.jku && typeof headers.jku !== 'string') throw 'JKU given, but it wasn\'t a string.'
  if (headers.jku && !headers.kid) throw 'JKU given, but corresponding kid wasn\'t supplied.'
  if (headers.jku && typeof headers.kid !== 'string') throw 'JKU given, but corresponding kid wasn\'t a string.'
  headers.alg = (typeof headers.alg === 'string') ? headers.alg : 'RSA256';
  headers.typ = (typeof headers.typ === 'string') ? headers.typ : 'JWT';
  headers.kty = (typeof headers.kty === 'string') ? headers.kty : prvJwk.kty;
  headers.iat = Math.floor(Date.now() / 1000);

  var assertion = KJUR.jws.JWS.sign(headers.alg, JSON.stringify(headers), data, KJUR.KEYUTIL.getKey(prvJwk)); 
  if (!assertion) throw 'Signature could not be generated with given inputs';

  if (inputAudit.signatures) {                                                   
    inputAudit.signatures.push(assertion);                                       
  } else {                                                                       
    inputAudit.signatures = [assertion];                                         
  }                                                                              
  return inputAudit;
}

function _serialize(obj) {

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
    + _.reduce(keys, function(acc,k,index) {
      if (!isarray) acc += '"'+k+'":'; // if an object, put the key name here
      acc += _serialize(obj[k]);
      if (index < keys.length-1) acc += ',';
      return acc;
    },"")
    + endtoken;
}
