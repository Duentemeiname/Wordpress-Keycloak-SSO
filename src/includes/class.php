<?php
class ksso_data {
    private $serverurl;
    private $realm;
    private $clientid;
    private $clientsecret;
    private $loginurl;
    private $logouturl;
    private $publickey;
    private $tokenendpoint;
    private $accountservice;

    public function __construct() 
    {
        $this->load_data_from_db();
        $this->build_login_url();
        $this->build_logout_url();
        $this->get_keycloak_data();
    }

    public function get_serverurl() 
    {
        return $this->serverurl;
    }

    public function get_realm() 
    {
        return $this->realm;
    }

    public function get_clientid() 
    {
        return $this->clientid;
    }

    public function get_clientsecret() 
    {
        return $this->clientsecret;
    }

    public function get_loginurl() 
    {
        return $this->loginurl;
    }

    public function get_logouturl() 
    {
        return $this->logouturl;
    }

    public function get_publickey() 
    {
        return $this->publickey;
    }

    public function get_tokenendpoint() 
    {
        return $this->tokenendpoint;
    }

    public function get_accountservice() 
    {
        return $this->accountservice;
    }

    private function load_data_from_db() 
    {
        global $wpdb;
        $table_name = $wpdb->prefix . 'ksso_data';

        $results = $wpdb->get_results("SELECT * FROM $table_name");

        if (empty($results)) 
        {
            wp_die('A critical error has occurred. Please inform the server administrator and report this error: Keycloak SSO is not configured.');
        }

        $this->serverurl = $results[0]->serverurl;
        $this->realm = $results[0]->realm;
        $this->clientid = $results[0]->clientid;
        $this->clientsecret = $results[0]->clientsecret;
    }

    private function build_login_url() 
    {
        if (empty($this->serverurl) || empty($this->realm) || empty($this->clientid)) 
        {
            wp_die('A critical error has occurred. Please inform the server administrator and report this error: Server URL, Realm or ClientID is not set.');
        }

        $this->loginurl = $this->serverurl . '/realms/' . $this->realm . '/protocol/openid-connect/auth?client_id=' . $this->clientid . '&redirect_uri=' . urlencode(site_url() . '/sso/login') . '&response_type=code&scope=openid';
    }

    private function build_logout_url() 
    {
        if (empty($this->serverurl) || empty($this->realm) || empty($this->clientid)) 
        {
            wp_die('A critical error has occurred. Please inform the server administrator and report this error: Server URL, Realm or ClientID is not set.');
        }

        $this->logouturl = $this->serverurl . '/realms/' . $this->realm . '/protocol/openid-connect/logout?post_logout_redirect_uri=' . urlencode(site_url()) . '&client_id=' . $this->clientid;
    }

    private function get_keycloak_data() 
    {
        try 
        {
            if (empty($this->serverurl) || empty($this->realm)) 
            {
                throw new Exception('Server URL or Realm is not set.');
            }
    
            $url = $this->serverurl . '/realms/' . $this->realm;
            
            $data = @file_get_contents($url);
    
            if ($data === false) 
            {
                $error = error_get_last();
                throw new Exception('Error fetching Keycloak data: ' . $error['message']);
            }

            $json = json_decode($data);
            $this->publickey = $json->public_key;
            $this->tokenendpoint = $json->{'token-service'};
            $this->accountservice = $json->{'account-service'};

            if(empty($this->publickey) || empty($this->tokenendpoint) || empty($this->accountservice)) 
            {
                throw new Exception('Public Key, Token Endpoint or Account Service is not set.');
            }
    
        } 
        catch (Exception $e) 
        {
            wp_die('A critical error has occurred. Please inform the server administrator and report this error: ' . $e->getMessage());
        }
    }
}