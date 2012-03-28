<?php
/*
 Version = 'alpha.0.1.Build.5';
 
*/
$Plop_salt = 'salt';
/*     Sanitize Inputs  
 return preg_replace("/[^A-Za-z0-9]/", "", $in);
*/

$Plop_action = ''.TxtOnlyStrict($_POST['V1']);   //action 
$Plop_secret = ''.TxtOnlyStrict($_POST['V2']);   //secret 
$Plop_msg = ''.TxtOnlyStrict($_POST['V3']);  //msg
$Plop_dest = ''.TxtOnlyStrict($_POST['V4']);  //dest

/*	Debug Area


$Plop_action = 'd';
$Plop_action = 'e';

$Plop_secret = 'Really hard to guess phrase'

$Plop_msg = array('1' => 'type','item2' => 'value1');
$Plop_msg = 'string';

$Plop_dest =
*/









/*    Flow 

	        Give direction
		to encrypted need		
		FROM stringencrypted to jsonarray
*/
Switch($Plop_action){


case 'e':
$sendenc =  base64_encode(json_encode(enc($Plop_salt,$Plop_secret,$Plop_msg))); 
echo $sendenc;
break;

case 'd':
$plob = json_decode(base64_decode($Plop_msg),true);
$out = Dcrpt($Plop_salt,$Plop_secret,$plob['iv'],$plob['Enc']);
echo base64_encode(json_encode($out['load_decrypted']));
break;

default:

}


//Functions

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

function TxtOnlyStrict($in){
//return only txt and numbers
 return preg_replace("/[^A-Za-z0-9]/", "", $in);
}


?>