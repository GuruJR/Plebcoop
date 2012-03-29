<?php

/*     Sanitize Inputs  

*/

$Plop_action = $_POST["v1"];  
$Plop_secret = $_POST["v2"];   
$Plop_msg = $_POST["v3"];  
header("Cache-Control: no-cache, must-revalidate"); // HTTP/1.1
header("Expires: Sat, 26 Jul 1997 05:00:00 GMT"); // Date in the past
/*
 Version = 'alpha.0.1.Build.6';
 
*/
$Plop_salt = 'salt';



/*	Debug Area
print_r($_POST);
 return preg_replace("/[^A-Za-z0-9]/", "", $in); is maybe too aggresive for base64
$Plop_dest = TxtOnlyStrict($_Post['v4']);  //dest

$Plop_action = 'd';
$Plop_action = 'e';

$Plop_secret = 'Really hard to guess phrase';

$Plop_msg = array('1' => 'type','item2' => 'value1');
$Plop_msg = 'string';

$Plop_dest = '' ;


$Plop_action = 'e';
$Plop_msg = 'msg';
$Plop_secret = 'key';
$Plop_action = 'd';
$Plop_msg = 'eyJpdiI6IlgxQnUydWlCaW5EQmxJQzk4QjNGb244cmZ6aWxXQTJUWTFISVc4dFBVcGM9IiwiRW5jIjoiU3dRRGRrZDdnRDJtTG12dzJ0NFJJU0JWYmpjbDRGb0ZKWjRHTDZqTDlIOD0ifQ==';
$Plop_secret = 'key';

2nd
test unit
woring
$Plop_action = 'e';
$Plop_msg = 'msg';
$Plop_secret = 'key';


  Flow 

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
echo $out;
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
    $unser = $decrypted;
  return  $unser ;
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
 // preg_replace("/[^A-Za-z0-9\=]/", "", $in);
preg_replace("/[^A-Za-z0-9\=]/", "", $in);
return $inutfted;
}


?>