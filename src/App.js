import React, { Component } from 'react';
import './App.css';
import FileDrop from 'react-file-drop';
import _ from 'lodash';
import fd from 'react-file-download'
import gv from '../generateVerify'
var Promise = require('bluebird').Promise; 
var agent = require('superagent-promise')(require('superagent'), Promise);

class App extends Component {

  componentWillMount() {
    this.setState({verifyStatus:null});
  }


//TODO: use eval to handle plain module.exports file
  handleFile(filelist, e, stateKey, fileExtension) {
    var reader = new FileReader();
    var file = filelist[0];
    if (!file) return false;
    if (file.name.substring(file.name.length-3, file.name.length) === fileExtension) {
      reader.onload = (upload) => {
        var obj = {};
        obj[stateKey] = upload.target.result.split('\n')[1];
        this.setState(obj);
      }
      reader.readAsText(file);
    }
  }

  serialize(obj) {
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
      acc += this.serialize(obj[k]);
      if (index < keys.length-1) acc += ',';
      return acc;
    },"")
    + endtoken;
  }

  unsignedAuditDropped(filelist, e) {
    var reader = new FileReader();
    var file = filelist[0];
    if (!file) return false;
    if (file.name.substring(file.name.length-4, file.name.length) === 'json') {

      reader.onload = (upload) => {
        this.setState({inputAudit: {filename: name, audit:JSON.parse(upload.target.result)}});
        this.signAudit();
      }
      reader.readAsText(file);
    }
  }

  signedAuditDropped(filelist, e) {
    var reader = new FileReader();
    var file = filelist[0];
    if (!file) return false;
    if (file.name.substring(file.name.length-4, file.name.length) === 'json') {

      reader.onload = (upload) => {
        this.setState({signedAudit: {filename: name, audit: JSON.parse(upload.target.result)}});
        this.verifyAudit();
      }
      reader.readAsText(file);
    }
  }

  verifyAudit() {
    var self = this;
    if (this.state.signedAudit) { //Audit file present.
      gv.verify(this.state.signedAudit.audit)
      .then(function(res) {
        console.log(res);
        self.setState({verifyStatus:res})
      })
      .catch((err) => {
        console.log(err);
      })
    }
  }

  signAudit() {
    if (this.state.inputAudit) { //Audit file present.
      var pubJwk = {
        kty: 'RSA',
        n: 'nrNguIQlBwNqNkKO1h0BhePImG_SXMknYaDC_ltwjHpdt139t1J2nkMLDKrqRcF2vlTG61dRYrYgPW55G8oU3Uuf4J0p2Lf5u6ZRvdSw1ep5gfLwWGWy22F-hx1DAKf3E6keTIBfcNejihEPQv9H9Fzy1-GJUzMYfrPi9E2kiaOTuFzGLkOKX5qnVBZZGYube4soOV6c18uz83UFBDs_3sYp89GrakH5jvwMHqV4e1qBv6p2BCXPoVYW6rUJjAAyQM9wN2h8jfkZtYTtV6KGeTj4EaAHr2fQacZFN77IIzRTL8flRLgDKns3QMdrbky43bvCRvjd_4rKCJ9onbDixw',
        e: 'AQAB'
      }
      var prvJwk = { 
        kty: 'RSA',
        n: 'nrNguIQlBwNqNkKO1h0BhePImG_SXMknYaDC_ltwjHpdt139t1J2nkMLDKrqRcF2vlTG61dRYrYgPW55G8oU3Uuf4J0p2Lf5u6ZRvdSw1ep5gfLwWGWy22F-hx1DAKf3E6keTIBfcNejihEPQv9H9Fzy1-GJUzMYfrPi9E2kiaOTuFzGLkOKX5qnVBZZGYube4soOV6c18uz83UFBDs_3sYp89GrakH5jvwMHqV4e1qBv6p2BCXPoVYW6rUJjAAyQM9wN2h8jfkZtYTtV6KGeTj4EaAHr2fQacZFN77IIzRTL8flRLgDKns3QMdrbky43bvCRvjd_4rKCJ9onbDixw',
        e: 'AQAB',
        d: 'jd73uRvQ6hsgaQ9JF5nokaPW4IcefHoKrZkEmFRwIfUGMHVi6e5bQhHXH-Tu95sCpxWsmhh-FguQeLp4o-IcktQXQbnd_fJB24HMkzI_P4yUQRpHyA5qPPpEHU-IZV7CXx4Rivw71enANh4YEaGa1pX9NgZWOD12SVZQrmt2it93A7jGFNiJYlRZSqXmiSRdg39v5G9hnxDUWdbN_bTrc8DJ6ZH15_nBxxZIWcZZavqXzabFsKTLWKhxsB1pVs9f9xKcuv_MzAbjOwe8y225_HCLUtevV0uMrHPl-x3gPN_hdSj9ZhGcMr8S6V_f6ONu1uvIpgj5rXGdwPUsfoPW4Q',
        p: '6uejaQUI_x2rDYjvucph3CgQ6MrB_2RsQ1HAu3fSIkvkN7gtFDgP4HvD4nchUZJ6_f4sXirKrWBOEYI4vyXoanBD9ZCSmLkzjBtwEGunndMSCtX8rXL9-MSZXSxS6_7auzUvoeMk-KrJ_zAf62K_13RT5polAQSedw-bf5wl6zc',
        q: 'rPPWwAhw7BnWaoy-a5zXYwhaCtcqaEegiBkCo4h90n0OOFzuTZzgN7g0karXv_B2hyidwybf2c35BNVSg_rjAX7QWmbPbIQz24DAUSJYEhFFDlAzhXJej23oFpJc7pLtAQgrSJ_XOP1NmCQl27Br4xesrkNRNb8D2ndZPdV3LPE',
       dp: 'UNRqJ14DLX3w-RRQoRahu9bRkrkKLi5JDpUYA6oEVabVndKzOEzeMbmEuu2ROndz-Og4LiL9YNFNq7qqeiO6KL3-tIYN252GvkRGuG_C2ozhnXbqnmh-Oda0ixoQYoJsk5SGkmcNtr9WCIhvw1hUePffUu9hoksLmB53vF5nsds',
       dq: 'ZjILMhuKxigaR4l0t1fM-aqksgUj_MxeMi09Hu53EppsfaeD9H5_Cs2g2nYt2C-5ifHZDsh4u1V3EIEQqgXkfyy05sYbSM7xaYGxof9-NObZfDStzOugrnXODxBbM2nD-7kdAmPYo8chQ4YQjLi5d0207p--a9i76SpepCfvrLE',
       qi: 'YlE9wO5yPCG12gp76BeivZtK4y-E6HO--o3s2uNs1nbXcBHzdoPOp0hfwI3FlIn3WHlLiy1uJ0pH1Nel8WJBs4E1IDUAFx1PLFNzWGC2JhhztFjXc5LFIo-JySJXElzJ5DhvRdQawKtSqtVuANKgg3CBSmadtH82OBdtaKv9mkQ'
      }
      var kid = 'DemoSite'
      var alg = 'RS256'
      var kty = 'RSA'
      var typ = 'JWT'
//      var jku = 'https://raw.githubusercontent.com/fpad/trusted-list/master/jku-test/jku-test.json'
      var signedAudit = gv.generate(this.state.inputAudit.audit, kid, alg, kty, typ, prvJwk, pubJwk, null)
      fd(JSON.stringify(signedAudit), 'signedAudit.json')
    }
  }

  getSampleAudit(evt) {
    var sampleAuditUrl = 'https://raw.githubusercontent.com/fpad/fpad-audit-sign-verify/master/unsignedAudit.json'
    return agent('GET', sampleAuditUrl)
    .end()
    .then(function onResult(res) {
      fd(res.text, 'samplePgfsAudit.json')
    })
  }

  render() {

    var auditTarget;
    var verifyState = this.state.verifyStatus;
    if (verifyState === null) {
      auditTarget = "audit-target"
    } else if (verifyState === true) {
      auditTarget = "audit-valid"
    } else if (verifyState === false) {
      auditTarget = "audit-invalid"
    }
    return (
      <div className="App">
        <div className="App-header">
          <h2>FPAD Audit Signature Generation and Verification</h2>
          <h3>Need a sample audit? <a onClick={(evt) => {this.getSampleAudit(evt)}}>Download Here</a></h3>
         <div className="App-instructions">
         </div>

        </div>
        <div className="App-content">
           <div className="App-sign">
            <h3>Sign an audit</h3>
            <div className="audit-target">
              Drag an audit here!
              <FileDrop 
                frame={document.createElement('div')}
                onDrop={(evt) => {this.unsignedAuditDropped(evt)}}
              />
            </div>
          </div>
          <div className="App-verify">
            <h3>Verify a signed audit</h3>
            <div className={auditTarget}>
              Drag a signed audit here!
              <FileDrop 
                className='signed-targ'
                frame={document.createElement("div")} 
                onDrop={(evt) => {this.signedAuditDropped(evt)}}
              />
            </div>
          </div>
        </div>
      </div>
    );
  }
}

export default App;
