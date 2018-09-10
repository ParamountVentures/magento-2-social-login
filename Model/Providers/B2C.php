<?php
/*!
* HybridAuth
* http://hybridauth.sourceforge.net | https://github.com/hybridauth/hybridauth
*  (c) 2009-2012 HybridAuth authors | http://hybridauth.sourceforge.net/licenses.html
*/

namespace Mageplaza\SocialLogin\Model\Providers;

use \Firebase\JWT\JWT;
use \phpseclib\Crypt\RSA;

/**
 * Hybrid_Providers_Instagram (By Sebastian Lasse - https://github.com/sebilasse)
 */
class B2C extends \Hybrid_Provider_Model_OAuth2
{
    // default permissions
    public $scope = "openid profile";

    // used when verifying the jwt
    private $RSA;
    private $JWT;    
    private $policy_qs;
    private $tenant;
    private $domain;

    /**
     * IDp wrappers initializer
     * @throws \Exception
     */
    function initialize()
    {
        parent::initialize();

        // Provider api end-points
        $this->tenant = $this->config["keys"]["tenant"];
        $this->domain = $this->config["keys"]["domain"];
        $this->policy_qs = $this->config["keys"]["policy"];
        //$this->key_url = "https://login.microsoftonline.com/" . $this->tenant . ".onmicrosoft.com/discovery/v2.0/keys?p=" . $this->policy_qs;
        $this->key_url = "https://" . $this->tenant . ".b2clogin.com/" . $this->domain . "/discovery/v2.0/keys?p=" . $this->policy_qs;
        $this->api->api_base_url  = "https://graph.windows.net";
        //$this->api->authorize_url = "https://login.microsoftonline.com/" . $this->tenant . ".onmicrosoft.com/oauth2/v2.0/authorize";
        $this->api->authorize_url = "https://" . $this->tenant . ".b2clogin.com/" . $this->domain . "/oauth2/v2.0/authorize";
        //$this->api->token_url     = "https://login.microsoftonline.com/" . $this->tenant . ".onmicrosoft.com/oauth2/v2.0/token?p=" . $this->policy_qs;
        $this->api->token_url     = "https://" . $this->tenant . ".b2clogin.com/" . $this->domain . "/oauth2/v2.0/token?p=" . $this->policy_qs;

        
        $this->JWT = new JWT();              
        $this->RSA = new RSA();
    }

    /**
     * security: Enforce signed requests
     */
    function generateSig($endpoint, $params, $secret)
    {
        $sig = $endpoint;
        ksort($params);
        foreach ($params as $key => $val) {
            $sig .= "|$key=$val";
        }
        
        return hash_hmac('sha256', $sig, $secret, false);
    }

    /**
     * load the user profile from the IDp api client
     * @return \Hybrid_User_Profile
     * @throws \Exception
     */
    function getUserProfile()
    {   
        // in B2C the profile data is stored in the token jwt, so decode this, verify it and extract the details
        // extract data from id_token        
        $result = $this->validate_id_token($this->api->id_token);

        if (!$result["success"]) {
            echo("Parsing the token failed.");
            exit();
        }

        $data = $result["payload"];

        $this->user->profile->identifier  = $data->oid;

        if (!empty($data->given_name)) {
            $this->user->profile->firstName = $data->given_name;
        }

        if (!empty($data->family_name)) {
            $this->user->profile->lastName = $data->family_name;
        } else {
            $this->user->profile->lastName = "[" . $this->tenant . "]";
        }
        
        if (!empty($data->emails))
        {
            $this->user->profile->email = $data->emails[0];
            $this->user->profile->emailVerified = true;
        }

        if (!empty($data->email))
        {
            $this->user->profile->email = $data->email;
        }

        if (!empty($this->user->profile->email)) {
            $this->user->profile->username = $this->user->profile->email;
        } else {
            $this->user->profile->username = $this->user->profile->identifier;
        }

        if (!empty($data->displayName)) {
            $this->user->profile->displayName = $data->displayName;
        } else {
            if (!empty($data->name)) {
                $this->user->profile->displayName = $data->name;
            }
            else {
                $this->user->profile->displayName = $this->user->profile->identifier;
            }
        }

        if (empty($data->email)) {
            $this->user->profile->email = $this->user->profile->displayName;

            // ensure we have an email as a default or it fails to parse
            if (strpos($this->user->profile->email, '@') === false ) {
                $this->user->profile->email = $this->user->profile->email .  "@logon.city";
            }
        }

        if (empty($this->user->profile->displayName)) {
            $this->user->profile->displayName = "my account";
        }      
        
        //var_dump($this->user->profile);
        //exit();
        return $this->user->profile;
    }

    /**
     * @param $id_token - h/t https://gist.github.com/rcosgrave/ec92938181096fd8847a38c9cc6a37d0
     * @return array
     */
    public function validate_id_token($id_token) {
        
        $used_key = $this->get_used_key($id_token);        
        $modulus = $this->convert_base64url_to_base64($used_key->n); // Alter to correct format
        $exponent = $this->convert_base64url_to_base64($used_key->e); // Alter to correct format
        
        $this->RSA->setPublicKey('<RSAKeyValue>
			<Modulus>' . $modulus . '</Modulus>
			<Exponent>' . $exponent . '</Exponent>
            </RSAKeyValue>');
            
        $public_key = $this->RSA->getPublicKey();
        try {
            $decoded = $this->JWT->decode($id_token, $public_key, array('RS256'));
        }
        catch (Exception $e) {
            return array("success" => false, "error" => "Unable to valid id_token with message: " .$e->getMessage());
        }
        return array("success" => true, "payload" => $decoded);
    }
    
    /**
     * Using the kid of the $id_token to match against available keys	
     * @param $id_token
     * @return mixed
     */
    private function get_used_key($id_token) {
        $token_parts = $this->get_id_token_parts($id_token);
        $header = json_decode(base64_decode($token_parts['header']));
        $available_keys = $this->get_available_keys();
        foreach ($available_keys as $available_key) {
            if ($available_key->kid == $header->kid) {
                return $available_key;
            }
        }
        return false;
    }
    
    /**
     * @param $id_token
     * @return array
     */
    private function get_id_token_parts($id_token) {
        $token_parts = explode(".", $id_token);
        $return['header'] = $token_parts[0];
        $return['payload'] = $token_parts[1];
        $return['signature'] = $token_parts[2];
        return $return;
    }    

    /**
     * @return object
     */
    private function get_available_keys() {
        $azure_keys = json_decode(file_get_contents($this->key_url));
        return $azure_keys->keys;
    }    

    /**
     * @param string $input
     * @return string
     */
    private function convert_base64url_to_base64($input="") {        
        $padding = strlen($input) % 4;
        if ($padding > 0) {
            $input .= str_repeat("=", 4 - $padding);
        }
        return strtr($input, '-_', '+/');
    }    
}
