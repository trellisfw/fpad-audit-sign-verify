'use strict'
const sha256 = require('js-sha256');
const KJUR = require('jsrsasign');
const _ = require('lodash');
const Promise = require('bluebird'); 
const agent = require('superagent-promise')(require('superagent'), Promise);
let trustedList;
let lastTrustedListRetrieved;

module.exports = {
  generate: generate,
  verify: verify,
}

//This function compares the hash given in the most recent signature's JWT payload to a
//reconstructed hash of the audit. The most recent signature (and also the signatures
//key if only one signature was present) should be omitted in the reconstructed hash.
//If the hashes match, we can conclude that content hasn't been modified.
function _isContentModified(auditIn) {
  let audit = _.cloneDeep(auditIn);
  if (!audit.signatures) return false
  if (audit.signatures.length === 0) return false

  //Get the decoded hashed audit in the signature JWT
  let auditJwt = audit.signatures[audit.signatures.length-1]
  let decoded = KJUR.jws.JWS.readSafeJSONString(KJUR.b64utoutf8(auditJwt.split(".")[1]));

  // Remove the last signature in the signatures key array for reconstruction.
  if (audit.signatures.length === 1) {
    delete audit.signatures;
  } else audit.signatures.pop();
 
  //Serialize and hash the given audit. 
  let reconstructedAudit = _serialize(audit);
  reconstructedAudit = sha256(reconstructedAudit);

  // Now compare
  return (decoded.hash !== reconstructedAudit) 
}

// This function reconstructs the headers for verification using KJUR. KJUR wants alg to be
// an array for some reason even though generating the JWT with alg as an array does not work. 
function _isVerified(auditJwt, headersIn, jwk) {
  let headers = _.cloneDeep(headersIn);
  let pubKey = KJUR.KEYUTIL.getKey(jwk);
  if (headers.alg) headers.alg = [headers.alg]
  if (headers.typ) headers.typ = [headers.typ]
  if (headers.iss) headers.iss = [headers.iss]
  if (headers.sub) headers.sub = [headers.sub]
  if (headers.aud) headers.aud = [headers.aud]
  if (headers.kty) headers.kty = [headers.kty]
  return KJUR.jws.JWS.verifyJWT(auditJwt, pubKey, headers);
}

function _isSignerTrusted(jwkHash) {
  if (!jwkHash) return false // For some reason, no hash of the key was included. Can't check. Don't trust!
  return (trustedList[jwkHash]) ? true : false;
}

function _getJwkFromHeaders(headers) {
  return Promise.try(() => {
//Handle JWK. The audit contained a JWK that can be directly used for verification
    if (headers.jwk) return headers.jwk;

//Handle JKU. The audit contained a JKU, which is a URL to a JWK set. An accompanying
//KID is needed in the headers to look up the particular JWK on the JKU.
    else if (headers.jku) {
      return agent('GET', headers.jku)
      .end()
      .then((jkuRes) => {
        let keySet = JSON.parse(jkuRes.text);
        let jwk;
        keySet.keys.forEach(function(key) {
          if (key.kid === headers.kid) {
            return key
          }
        })
        return null;//No matching KID found in the JKU keyset!
      })
    } else return null; //Niether a JKU nor a JWK were supplied.
  })
}

// Initialize the trusted list or redownload it if its over a day old.
function _fetchTrustedList() {
  return Promise.try(() => {
    if (!trustedList || (lastTrustedListRetrieved < Date.now()-864e5)) {
      return agent('GET', 'https://raw.githubusercontent.com/fpad/trusted-list/master/keys.json')
      .end()
      .then((res) => {
//Set the trustedList global variables so they do not to be requested on subsequent verifications (within 24 hours)
        lastTrustedListRetrieved = Date.now()
        return trustedList = JSON.parse(res.text)
      })
    } else return trustedList
  })
}

// This function verifies the given audit. The audit should contain the public key source
// necessary to verify itself (either JWK or JKU).
function verify(audit) {
  return Promise.try(() => {
// Check that a signature is present and parse out the given JWT headers
    if (!audit.signatures) throw new Error('Audit has no signatures to be verified.')
    if (audit.signatures.length === 0) throw new Error('Audit has no signatures.')
    let auditJwt = audit.signatures[audit.signatures.length-1]
    let headers = KJUR.jws.JWS.readSafeJSONString(KJUR.b64utoutf8(auditJwt.split(".")[0]))
    if (!headers) throw new Error('Malformed signature (JWT headers couldn\'t be parsed).')

// Perform verification against the trusted list.
    return _fetchTrustedList().then(() => {
      return _getJwkFromHeaders(headers).then((jwk) => {
        if (!jwk) throw new Error('A JWK or JKU must be included to verify the audit. A JKU requires an accompanying KID in the headers to look up the particular JWK.')
//TODO: need some function that tests whether the JWK is generally a valid JWK thingy. The test on jwk.n is sort of doing this.
        if (!_isSignerTrusted(jwk.n)) throw new Error('Audit signature is valid. The signer is not on the trusted list.') // Its not on the trusted list. Don't trust!
        if (!_isVerified(auditJwt, headers, jwk)) throw new Error('Audit signature cannot be verified.')
        if (_isContentModified(audit)) throw new Error('Audit signature is valid. Signer is trusted. The Audit contents have been modified.')
        return true
      })
    })
  })
}

//This function accepts an input audit along with the JWT headers necessary to 
//construct a JWT and appends an additional signature to the signatures key of 
//the audit.
function generate(inputAudit, prvJwk, headers) {
  return Promise.try(() => {
    if (!prvJwk) throw 'Private key required to sign the audit.';
    let data = _serialize(inputAudit);
    if (!data) throw 'Audit could not be serialized.'
    data = {hash: sha256(data)};
    if (!data) throw 'Audit could not be hashed.'

    if (!headers.jwk && !headers.jku) throw 'Either a public JWK key or a JKU must be included for downstream verification of the given private key.' 
    if (headers.jku && typeof headers.jku !== 'string') throw 'JKU given, but it wasn\'t a string.'
    if (!headers.kid) throw 'KID header wasn\'t supplied.'
    if (typeof headers.kid !== 'string') throw 'KID wasn\'t a string.'

// Defaults
    headers.alg = (typeof headers.alg === 'string') ? headers.alg : 'RSA256';
    headers.typ = (typeof headers.typ === 'string') ? headers.typ : 'JWT';
    headers.kty = (typeof headers.kty === 'string') ? headers.kty : prvJwk.kty;
    headers.iat = Math.floor(Date.now() / 1000);

    let assertion = KJUR.jws.JWS.sign(headers.alg, JSON.stringify(headers), data, KJUR.KEYUTIL.getKey(prvJwk)); 
    if (!assertion) throw 'Signature could not be generated with given inputs';

    if (inputAudit.signatures) {                                                   
      inputAudit.signatures.push(assertion);                                       
    } else inputAudit.signatures = [assertion];
    return inputAudit;
  })
}

function _serialize(obj) {

  if (typeof obj === 'number') throw new Error('You cannot serialize a number with a hashing function and expect it to work.  Use a string.');
  if (typeof obj === 'string') return '"'+obj+'"';
  if (typeof obj === 'boolean') return (obj ? 'true' : 'false');
  // Must be an array or object
  let isarray = _.isArray(obj);
  let starttoken = isarray ? '[' : '{';
  let   endtoken = isarray ? ']' : '}';

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
