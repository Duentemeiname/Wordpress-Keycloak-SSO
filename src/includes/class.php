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

    public function __construct($serverurl = null, $realm = null, $clientid = null, $clientsecret = null) 
    {
        if ($serverurl !== null && $realm !== null && $clientid !== null && $clientsecret !== null) {
            $this->serverurl = sanitize_text_field($serverurl);
            $this->realm = sanitize_text_field($realm);
            $this->clientid = sanitize_text_field($clientid);
            $this->clientsecret = sanitize_text_field($clientsecret);
            $this->creat_db_entry();
        }

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

    private function creat_db_entry()
    {
        global $wpdb;
        $table_name = $wpdb->prefix . 'ksso_data';

        if(empty($this->serverurl) || empty($this->realm) || empty($this->clientid) || empty($this->clientsecret)) 
        {
            wp_die('A critical error has occurred. Please inform the server administrator and report this error: Server URL, Realm, ClientID or ClientSecret is not set.');
        }

        $this->serverurl = rtrim($this->serverurl, '/');

        $wpdb->replace($table_name, array('id'=> 1, 'serverurl' => $this->serverurl, 'realm' => $this->realm, 'clientid' => $this->clientid, 'clientsecret' => $this->clientsecret));
    }

    private function load_data_from_db() 
    {
        global $wpdb;
        $table_name = $wpdb->prefix . 'ksso_data';

        $results = $wpdb->get_results("SELECT * FROM $table_name");

        if (empty($results) && (isset($_GET['page']) && $_GET['page'] === 'ksso-plugin')) 
        {
            $this->serverurl = '';
            $this->realm = '';
            $this->clientid = '';
            $this->clientsecret = '';
            return;
        }
        else if (empty($results))
        {
            wp_die('A critical error has occurred. Please inform the server administrator and report this error: Keycloak SSO is not configured.');
            return;
        }
        else
        {
            $this->serverurl = $results[0]->serverurl;
            $this->realm = $results[0]->realm;
            $this->clientid = $results[0]->clientid;
            $this->clientsecret = $results[0]->clientsecret;
            return;
        }
    }

    private function build_login_url() 
    {
        if (empty($this->serverurl) || empty($this->realm) || empty($this->clientid)) 
        {
            if (isset($_GET['page']) && $_GET['page'] === 'ksso-plugin') 
            {
                return;
            }
            wp_die('A critical error has occurred. Please inform the server administrator and report this error: Server URL, Realm or ClientID is not set.');
        }

        $this->loginurl = $this->serverurl . '/realms/' . $this->realm . '/protocol/openid-connect/auth?client_id=' . $this->clientid . '&redirect_uri=' . urlencode(site_url() . '/sso/login') . '&response_type=code&scope=openid';
    }

    private function build_logout_url() 
    {
        if (empty($this->serverurl) || empty($this->realm) || empty($this->clientid)) 
        {
            if (isset($_GET['page']) && $_GET['page'] === 'ksso-plugin') 
            {
                return;
            }
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
                if (isset($_GET['page']) && $_GET['page'] === 'ksso-plugin') 
                {
                    return;
                }
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
    private $roles = array(); // keycloak role => wordpress role
    private $availableWordPressRoles = array();

    public function __construct($kc_role = null , $wp_role = null) 
    {
        $this->write_log('ksso_roles::__construct()');

        if($kc_role !== null && $wp_role !== null) 
        {
            $this->add_rolemapping($kc_role, $wp_role);
        }
        else
        {
            $this->load_rolemapping_from_db();
        }
        $this->available_wordpress_roles();
    }

    public function get_roles() 
    {
        return $this->roles;
    }

    public function get_available_wordpress_roles() 
    {
        return $this->availableWordPressRoles;
    }

    public function delete_rolemapping($id) 
    {
        global $wpdb;
        $table_name = $wpdb->prefix . 'ksso_roles';
    
        if (!is_numeric($id) || $id <= -1) 
        {
            throw new Exception('Ungültige ID: ' . $id);
        }
    
        $deleted = $wpdb->delete($table_name, array('id' => intval($id)));
    
        if ($deleted === false) 
        {
            throw new Exception('Fehler beim Löschen des Rollenmappings mit der ID: ' . $id);
        } 
        elseif ($deleted == 0) 
        {
            throw new Exception('Kein Rollenmapping mit der ID ' . $id . ' gefunden.');
        }
    
        $this->load_rolemapping_from_db();
    }
    

    private function available_wordpress_roles() 
    {
        global $wp_roles;
        $this->availableWordPressRoles = $wp_roles->roles;
    }

    private function add_rolemapping($kc_role, $wp_role) 
    {
        global $wp_roles;

        $this->write_log('ksso_roles::add_rolemapping() - ' . $kc_role . ' - ' . $wp_role);
        $kc_role = sanitize_text_field($kc_role);
        $wp_role = sanitize_text_field($wp_role);

        if (strlen($kc_role) == 0 || strlen($wp_role) == 0 || strlen($kc_role) > 255 || strlen($wp_role) > 255) 
        {
            throw new Exception('Role names must be between 1 and 255 characters.');
        }

        if (!isset($wp_roles->roles[$wp_role])) 
        {
            throw new Exception('Role does not exist.' . $wp_role);
        }

        $this->add_rolemapping_to_db($kc_role, $wp_role);
    }

    public function user_add_rolemapping($userid, $user_jwt_token)
    {
        $this->write_log('ksso_roles::user_add_rolemapping() - ' . $userid . ' - ' . print_r($user_jwt_token, true));
        $userroles_kc = $user_jwt_token->realm_access->roles;
        $size = count($userroles_kc);

        if (sizeof($this->roles) == 0) 
        {
            return;
        }

        $user = new WP_User($userid);
        foreach ($user->roles as $role) 
        {
            $user->remove_role($role);
        }

        for ($i = 0; $i < $size; $i++) 
        {
            $role = $userroles_kc[$i];
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

        $wpdb->insert($table_name, array('keycloak_role_name' => $kc_role, 'wordpress_role_name' => $wp_role));
        $this->load_rolemapping_from_db();
    }

    private function load_rolemapping_from_db() 
    {
        global $wpdb;
        $table_name = $wpdb->prefix . 'ksso_roles';

        $results = $wpdb->get_results("SELECT * FROM $table_name");

        if (empty($results) && (isset($_GET['page']) && $_GET['page'] === 'ksso-plugin')) 
        {
            $results = array();
            return;
        }
        else if (empty($results))
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