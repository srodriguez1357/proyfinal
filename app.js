const express = require("express");
const multer = require('multer');
const bodyParser = require('body-parser');
const JsonDB = require('node-json-db').JsonDB;
const Config = require('node-json-db/dist/lib/JsonDBConfig').Config;
const uuid = require("uuid");
const speakeasy = require("speakeasy");
const QRCode = require('qrcode');
const fs     = require('fs');
const nacl   = require('tweetnacl');
const util   = require('tweetnacl-util');
const scrypt = require('scryptsy');
//const { AsyncResource } = require("async_hooks");

const dir = 'cifrados';
const dir2 = 'textos';
const upload = multer({dest: './textos'});
const app = express();

let salt;
let nonce;

var db = new JsonDB(new Config("myDataBase", true, false, '/'));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.get('/',(req, res) =>{
  res.render('index.ejs', {root: __dirname});
});


app.post("/api/regist", (req, res) => {
  const id = uuid.v4();
  try {
    const path = `/user/${id}`;
    // Create temporary secret until it it verified
    const temp_secret = speakeasy.generateSecret();
    res.json({ id, secret: temp_secret.base32 })
    QRCode.toDataURL(temp_secret.otpauth_url, function(err, data_url) {
      console.log(data_url);
      res.write('<img src="' + data_url + '">');
  });
    // Create user in the database
    db.push(path, { id, temp_secret });
    // Send user id and base32 key to user
    
  } catch(e) {
    console.log(e);
    res.status(500).json({ message: 'Error generating secret key'})
  }
})

app.post("/api/register", (req, res) => {
  res.render('newuser.ejs', {root: __dirname});
});

app.post("/api/newuser", (req, res) => {
  const { userId, secret } = req.body;
  const id = uuid.v4();
  try {
    const path = `/user/${userId}`;
    const temp_secret = speakeasy.generateSecret();
    db.push(path, { email:userId,pass:secret,token:temp_secret });
    res.json({ id, secret: temp_secret.base32 })
    QRCode.toDataURL(temp_secret.otpauth_url, function(err, data_url) {
        console.log(data_url);
        res.write('<img src="' + data_url + '">');
    });
    
    //res.render('main.ejs', {root: __dirname});
  } catch(e) {
    console.log(e);
    res.status(500).json({ message: 'Error generating secret key'})
  }
});

app.post('/enviar', upload.single('archivo'), (req, res) =>
{
   res.send('Archivo subido exitosamente');
});

app.post("/api/verify", (req,res) => {
  const { userId, token } = req.body;
  try {
    const path = `/user/${userId}`;
    const user = db.getData(path);
    console.log({ user })
    const { base32: secret } = user.temp_secret;
    const verified = speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token
    });
    if (verified) {
      db.push(path, { id: userId, secret: user.temp_secret });
      res.json({ verified: true })
    } else {
      res.json({ verified: false})
    }
  } catch(error) {
    console.error(error);
    res.status(500).json({ message: 'Error retrieving user'})
  };
})

app.post("/api/validate", (req,res) => {
  const { userId, token } = req.body;
  try {
    const path = `/user/${userId}`;
    const user = db.getData(path);
    console.log({ user })
    const { base32: secret } = user.secret;
    const tokenValidates = speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
      window: 1
    });
    if (tokenValidates) {
      res.render('textos.ejs');
    } else {
      res.json({ validated: false})
    }
  } catch(error) {
    console.error(error);
    res.status(500).json({ message: 'Error retrieving user'})
  };
})

app.post('/cifrados', (root,res)=>{
  fs.readdir(dir, (err, files) => {
      if (err) {
          throw err;
      }
      files.forEach(file => {
          console.log(file);         
      });
      res.send(files);
});
});

app.post('/decifrados', (root,res)=>{
  fs.readdir(dir2, (err, files) => {
      if (err) {
          throw err;
      }
      files.forEach(file => {
          console.log(file);         
      });
      res.send(files);
});
});

app.post('/cifrar', (req, res)=>{
  let password  = 'salem';
  salt = nacl.randomBytes(16);
  console.log("salt:", salt); 
  let N = 16384; 
  let r = 8; 
  let p = 1; 
  let public = scrypt(password, salt, N, r, p, nacl.secretbox.keyLength);
  texto = fs.readFileSync('./textos/confidencial.txt', 'utf-8'); 
  let secret_msg = util.decodeUTF8(texto); 
 // let salt = nacl.randomBytes(16);
  console.log("salt:", salt); 
  //let key = scrypt(password, salt, N, r, p, nacl.secretbox.keyLength);
  console.log(public);
  let nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
  console.log("nonce:", nonce);
  let encrypted = nacl.secretbox(secret_msg, nonce, public);
  encrypted = util.encodeBase64(encrypted);

  fs.writeFile('./cifrados/secreto.txt', encrypted, 'ascii', function(err) { 
      if (err) {
        console.log(err);
      } else {
        res.send('El archivo ha sido cifrado');
      }
    });
});

app.post('/decifrar', (req, res)=>{
let password = 'salem';
salt = nacl.randomBytes(16);
let N = 16384;
let r = 8; 
let p = 1; 
let private = scrypt(password, salt, N, r, p, nacl.secretbox.keyLength);
//let key = scrypt(password, salt, N, r, p, nacl.secretbox.keyLength);
let content = fs.readFileSync('./cifrados/secreto.txt', 'ascii'); 
console.log(content);
let encrypted = util.decodeBase64(content);
let decrypted = nacl.secretbox.open(encrypted, nonce, private); 
decrypted = util.encodeUTF8(decrypted);
if(String(texto) == String(decrypted)){
  console.log('Firma verificada');
  res.send('Firma verificada con éxito');
  fs.writeFile('./decifrados/yanosecreto.txt', decrypted, 'ascii', function(err) { 
    if (err) {
      console.log(err);
    } else {
      res.send('El archivo ha sido decifrado');
    }
  });
}
else{
  console.log('Firma errónea');
}



});

const port = 9000;

app.listen(port, () => {
  console.log(`App is running on PORT: ${port}.`);
});