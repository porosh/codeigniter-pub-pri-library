<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Pencryption {

    public function __construct() {
        
    }
    public function generatePublicPrivateKeys($destinationPath = NULL) {
        
        $privateKey = openssl_pkey_new(array(
            "private_key_bits" => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ));
        
        if($destinationPath != NULL){
            
            if(!file_exists($destinationPath)){
                if (!mkdir($destinationPath, 0777, true)) {
                    //die('Failed to create folders...');
                }
            }
            
            $publicKeyPath = $destinationPath.'/public.key';
            $privateKeyPath = $destinationPath.'/private.key';

            // Save the private key to private.key file. Never share this file with anyone.
            openssl_pkey_export_to_file($privateKey, $privateKeyPath);

            // Generate the public key for the private key
            $a_key = openssl_pkey_get_details($privateKey);
            // Save the public key in public.key file. Send this file to anyone who want to send you the encrypted data.
            file_put_contents($publicKeyPath, $a_key['key']);

            // Free the private Key.
            openssl_free_key($privateKey);
            
            return array(
                'private_key' => $privateKeyPath,
                'public_key'  => $publicKeyPath
            );
        }
        else {
            $config = array(
                "private_key_bits" => 2048,
                "private_key_type" => OPENSSL_KEYTYPE_RSA,
            );

            // Create the private and public key
            $res = openssl_pkey_new($config);

            // Extract the private key from $res to $privKey
            openssl_pkey_export($res, $privKey);

            // Extract the public key from $res to $pubKey
            $pubKey = openssl_pkey_get_details($res);
            $pubKey = $pubKey["key"];
            
            return array(
                'private_key' => $privKey,
                'public_key'  => $pubKey
            );
        }
    }
    
    
    public function encrypt($plaintext, $publicKeyPath){
        
        $plaintext = gzcompress($plaintext);
 
        // Get the public Key of the recipient
        $publicKey = openssl_pkey_get_public($publicKeyPath);//'file:///path/to/public.key'
        $a_key = openssl_pkey_get_details($publicKey);

        // Encrypt the data in small chunks and then combine and send it.
        $chunkSize = ceil($a_key['bits'] / 8) - 11;
        $output = '';

        while ($plaintext)
        {
            $chunk = substr($plaintext, 0, $chunkSize);
            $plaintext = substr($plaintext, $chunkSize);
            $encrypted = '';
            if (!openssl_public_encrypt($chunk, $encrypted, $publicKey))
            {
                die('Failed to encrypt data');
            }
            $output .= $encrypted;
        }
        openssl_free_key($publicKey);

        // This is the final encrypted data to be sent to the recipient
        return $output;
    }
    
    public function decrypt($encryptedData, $privateKeyPath){
        
        // Get the private Key
        if (!$privateKey = openssl_pkey_get_private($privateKeyPath)) //'file:///path/to/private.key'
        {
            die('Private Key failed');
        }
        $a_key = openssl_pkey_get_details($privateKey);

        // Decrypt the data in the small chunks
        $chunkSize = ceil($a_key['bits'] / 8);
        $output = '';

        while ($encrypted)
        {
            $chunk = substr($encrypted, 0, $chunkSize);
            $encrypted = substr($encrypted, $chunkSize);
            $decrypted = '';
            if (!openssl_private_decrypt($chunk, $decrypted, $privateKey))
            {
                die('Failed to decrypt data');
            }
            $output .= $decrypted;
        }
        openssl_free_key($privateKey);

        // Uncompress the unencrypted data.
        $output = gzuncompress($output);
    }

    private function writeToFile($filename){
        if (is_writable($filename)) {
            if (!$handle = fopen($filename, 'w')) {
                 return array(
                    'type' => 'error',
                    'message' => $filename,' faield to open file'
                );
            }
            if (fwrite($handle, $somecontent) === FALSE) {
                return array(
                    'type' => 'error',
                    'message' => $filename,' faield to write'
                );
            }
            fclose($handle);
            
            return array(
                'type' => 'success',
                'message' => 'content successfully written to '.$filename,
            );

        } else {
            return array(
                'type' => 'error',
                'message' => $filename,' is not writable'
            );
        }
    }
}

