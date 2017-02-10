import React, { Component } from 'react';
import './App.css';
import FileDrop from 'react-file-drop';
import FileReader from 'filereader';
import _ from 'lodash';
var clientAuth = require('jwt-bearer-client-auth');
var originalDoc = require('../../PGFS - HarvestCrew.js');
var sha256 = require('js-sha256');
var FileInput = require('react-file-input');

class App extends Component {

  pubFileDropped(file, evt){
    console.log('dropped into pub file drop target')
    if (!file) return false;
    if (file[0].name.substring(file[0].name.length-3, file[0].name.length) === 'pub') {
      console.log(file);
      this.setState({pubFile: file[0]});
    }
  }

  pemFileDropped(file, evt) {
    console.log('dropped into pem file drop target')
    console.log(evt);
    if (!file) return false;
    if (file[0].name.substring(file[0].name.length-3, file[0].name.length) === 'pem') {
      console.log(file);
      this.setState({pemFile: file[0]});
    }
  }

  pemFileSelected(evt) {
    console.log(evt);
    console.log('dropped into pem file drop target')
    //if (!file) return false;
   // if (file[0].name.substring(file[0].name.length-3, file[0].name.length) === 'pem') {
    //  console.log(file);
     // this.setState({pemFile: file[0]});
   // }
  }

  unsignedAuditDropped(file, evt) {
    console.log('dropped into unsigned audit drop target')
    this.setState({unsignedAudit: file[0]});
  }

  signedAuditDropped(file, evt) {
    console.log('dropped into signed audit drop target')
    this.setState({signedAudit: file[0]});
  }
/*
  verifyAuditButtonClicked() {
    if () {
      //Audit file present.
      if () {
        //Key file also present. Create signed audit.
      
      } else {
        console.log('');
      }
    } else {
      console.log('');
    }
  }
*/
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

  signAuditButtonClicked() {
//    if (this.state.unsignedAudit) {
    //Audit file present.
      if (this.state.pemFile) {
      //Key file also present. Create signed audit.
        var fr = new FileReader();
        fr.onload = (function(theFile){
          var fileName = theFile.name;
          return function(e){
            console.log(fileName);
            console.log(e.target.result);
          };
        });

        console.log(this.state.pemFile);
        var privatePem = fr.readAsText(this.state.pemFile);
/*        
        console.log('...data serialized');
        var data = this.serialize(data);
        console.log('...data hashed with SHA256');
        data = sha256(data);
        var key = {
          kid: 'abc123',
          kty: 'PEM',
          pem: privatePem
        };
        var issuer = 'aksdfj2w3';
        var clientId = 'ocjvS38kjxfa3JFXal342';
        var tokenEndpoint = 'https://api.example.org/token';
        var expiresIn = 60;
        var options = {
          algorithm: 'RS256',
          payload: data,
          headers: {
            alg: 'RS256',
            typ: 'JWT',
          }
        };

        var assertion = clientAuth.generate(key, issuer, clientId, tokenEndpoint, expiresIn, options);

        if (originalDoc.signatures) {
          originalDoc.signatures = originalDoc.signatures.push(assertion);
        } else {
          originalDoc.signatures = [assertion];
        }
*/
      } else {
        console.log('key file needed.');
      }
//    } else {
//      console.log('audit file needed');
//    }
  }

  render() {

    return (
      <div className="App">
        <div className="App-header">
          <h2>FPAD Audit Signature Generation and Verification</h2>
         <div className="App-instructions">
            <h3>1. Generate a Private/Public Keypair</h3>
            <ol>
              <li>
               Generate a private key named "private.pem": <code>openssl genrsa -des3 -out private.pem 2048</code> 
              </li>
              <li>
               Generate a public key named "public.pub": <code>openssl rsa -in private.pem -outform PEM -pubout -out public.pub</code> 
              </li>
            </ol>
          </div>

        </div>
        <div className="App-content">
           <div className="App-sign">
            <h3>Sign an audit</h3>
            <div className="private-pem-target">
              Drag your .pem file here!
              <FileDrop 
                frame={document.createElement('div')}
                onDrop={(files, evt) => {this.pemFileDropped(files, evt)}}>
              </FileDrop>
            </div>
            <FileInput name="myImage"
               accept=".pem,.pub,.js"
               placeholder="My Image"
               className="inputClass"
               onChange={(evt) =>{this.pemFileSelected(evt)}} />
            <div className="unsigned-audit-target">
              Drag an audit here!
              <FileDrop 
                frame={document.createElement('div')}
                onDrop={(evt) => {this.unsignedAuditDropped(evt)}}
              />
            </div>
            <button
              className='sign-audit-button'
              onClick={(evt)=> {this.signAuditButtonClicked(evt)}}>
              Generate Signed Audit
            </button>
          </div>
          <div className="App-verify">
            <h3>Verify a signed audit</h3>
            <div className="public-pub-target">
              Drag your .pub file here!
              <FileDrop 
                frame={document.createElement("div")} 
                onDrop={(evt) => {this.pubFileDropped(evt)}}
              />
            </div>
            <div className="signed-audit-target">
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
