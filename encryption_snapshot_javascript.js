const crypto = require('crypto');
var seedrandom = require('seedrandom');
var base64 = require('base-64');
var utf8 = require('utf8');


var salt = '123';
var m_pass = 'abc'
var password = 'xyz';

function makeSalt(salt) {
    Math.seedrandom(salt);
    var randstart = Math.random();
    var buffer = new Buffer(randstart.toString(), 'utf8');
    return gsalt =crypto.createHash('sha512').update(buffer).digest('hex');
}

var gsalt = makeSalt(salt);
console.log('gsalt', gsalt);


function key_for_acc_pass(m_pass) {
    var m_pass_ba = new Buffer(m_pass, 'utf8');
    var gsalt_ba = new Buffer(gsalt, 'utf8');
    var m_pass_ba_hash_str =crypto.createHash('sha512').update(m_pass_ba).update(gsalt_ba).digest('hex');
    return m_pass_ba_hash_str;

}

var encryption_decryption_key = key_for_acc_pass(m_pass);
console.log('encryption_decryption_key', encryption_decryption_key);

// to encrypt password:

function encrypt_it(plain_text, key) {
    var m_pass_ba_hash_str_ba = new Buffer(key, 'utf8');
    var plain_text_ba = new Buffer(plain_text, 'utf8');
    var cipher_text = [];
    for (var i = 0; i < plain_text_ba.length; i++) {
        var ord_now = plain_text_ba[i] ^ m_pass_ba_hash_str_ba[i];
        cipher_text.push(ord_now);
    };
    var cipher_text_ba = new Buffer(cipher_text, 'utf8');
    var cipher_text_ba_b64_str = base64.encode(cipher_text_ba, 'utf8');
    return cipher_text_ba_b64_str;
}

var encrypted = encrypt_it(password, encryption_decryption_key);
console.log('encrypted password: ', encrypted);


// to decrypt password:

function decrypt_it(get_key, cipher_text_ba_b64_str) {
    var textDecode = base64.decode(cipher_text_ba_b64_str, 'utf8');
    var cipher_text_ba_b64_str_decode = new Buffer(textDecode, 'utf8');
    var m_pass_byte_hash_str = get_key;
    var m_pass_byte_hash_str_byte = new Buffer(m_pass_byte_hash_str, 'utf8');
    var get_it_back = []
    for (var i = 0; i < textDecode.length; i++) {
        var re_ord = m_pass_byte_hash_str_byte[i] ^ cipher_text_ba_b64_str_decode[i];
        var recovered = String.fromCharCode(re_ord);
        get_it_back.push(recovered);
    };
    var plain_text_back = get_it_back.join('');
    return plain_text_back;
}

console.log('password decrypted as: ',decrypt_it(key_for_acc_pass(m_pass), encrypted));

//play around with the variables. Example enter any other string like 'xyz' or something
// instead of m_pass in the above function
//console.log('password decrypted as: ',decrypt_it(key_for_acc_pass('xyz), encrypted));
// and the wrong master password will give you
// an incorrect answer.



