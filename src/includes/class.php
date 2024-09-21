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

class ksso_roles {
    private $roles = array();

    public function __construct() 
    {
        $this->write_log('ksso_roles::__construct()');
        $this->load_rolemapping_from_db();
    }

    public function add_rolemapping($kc_role, $wp_role) 
    {
        $this->write_log('ksso_roles::add_rolemapping() - ' . $kc_role . ' - ' . $wp_role);
        $kc_role = sanitize_text_field($kc_role);
        $wp_role = sanitize_text_field($wp_role);

        if (strlen($kc_role) == 0 || strlen($wp_role) == 0 || strlen($kc_role) > 255 || strlen($wp_role) > 255) 
        {
            throw new Exception('Role names must be between 1 and 255 characters.');
        }

        if (!isset($wp_roles->roles[$wp_role])) 
        {
            throw new Exception('Role does not exist.');
        }

        $this->add_rolemapping_to_db($kc_role, $wp_role);
    }

    public function user_add_rolemapping($userid, $user_jwt_token)
    {
        $this->write_log('ksso_roles::user_add_rolemapping() - ' . $userid . ' - ' . print_r($user_jwt_token, true));
        $userroles = $user_jwt_token->realm_access->roles;
        $size = count($userroles);

        if (sizeof($this->roles) == 0) 
        {
            return;
        }

        for ($i = 0; $i < $size; $i++) 
        {
            $role = $userroles[$i];
            if (array_key_exists($role, $this->roles)) 
            {
                $wp_role = $this->roles[$role];
                $user = new WP_User($userid);
                $user->set_role($wp_role);
            }
        }
    }

    private function add_rolemapping_to_db($kc_role, $wp_role) 
    {
        global $wpdb;
        $table_name = $wpdb->prefix . 'ksso_roles';

        $wpdb->insert($table_name, array('keycloal_role_name' => $kc_role, 'wordpress_role_name' => $wp_role));
        $this->load_rolemapping_from_db();
    }

    private function load_rolemapping_from_db() 
    {
        global $wpdb;
        $table_name = $wpdb->prefix . 'ksso_roles';

        $results = $wpdb->get_results("SELECT * FROM $table_name");

        if (empty($results)) 
        {
            return;
        }

        foreach ($results as $result) 
        {
            $this->roles[$result->keycloak_role_name] = $result->wordpress_role_name;
        }
    }

    private function write_log($message)
    {
        $log_file = WP_CONTENT_DIR . '/log/sso.log';
        file_put_contents($log_file, date("Y-m-d H:i:s") . " - " . $message . PHP_EOL, FILE_APPEND);

    }
}