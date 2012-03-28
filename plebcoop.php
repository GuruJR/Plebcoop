
<?php
function Dcrpt($salt,$secret,$Base64iv,$Base64encrypted)
{

    // Decoding
    $plain = $Base64encrypted;
    $decoded = base64_decode($plain);
    $iv = base64_decode($Base64iv);
    $k = mhash(MHASH_SHA512, $secret.$salt);
    // Decrypting

    $decrypted = trim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $k, $decoded, MCRYPT_MODE_CBC, $iv));

    // Deserializing & loading
    $unser = json_decode($decrypted,true);
  return array('load_decrypted' => $unser);
}

function enc($salt,$secret,$unsecurarr){

    // Serialization
    $serialized = json_encode($unsecurarr);
 //set iv
    $iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CBC);
    $iv = mcrypt_create_iv($iv_size, MCRYPT_DEV_URANDOM);
    
    //basic key from secret
   $k = mhash(MHASH_SHA512, $secret.$salt);
   //To create an  advanced Full key Be low
   //$k_size = mcrypt_get_key_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CBC)
   //$k = mcrypt_create_iv( mcrypt_get_key_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CBC);
    // Encrypting

    $encrypted = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $k, $serialized, MCRYPT_MODE_CBC, $iv);

    // Encoding & output
    $encoded = base64_encode($encrypted);
    $ivencoded =  base64_encode($iv);

    return array('iv' => $ivencoded,
  /* 
  // 'Secret' => $secret,
  //'Returned_iv_seed' => $iv, 
  //'Returned_Plain' => $serialized,
  //  'Returned_Encr' => $encrypted,
  */
  'Enc' => $encoded);

}
$test = array('1' => 'type','item2' => 'value1');
$sendenc =  base64_encode(json_encode(enc('salt','secret',$test))); 
$plob = json_decode(base64_decode($sendenc),true);

$out= Dcrpt('salt','secret',$plob['iv'],$plob['Enc']);

print_r($sendenc);
print_r($out['load_decrypted']);
?>