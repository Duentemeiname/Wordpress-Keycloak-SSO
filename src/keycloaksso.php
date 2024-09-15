<?php

/*
 * Plugin Name:       Keycloak SSO Plugin
 * Plugin URI:        https://docs.duentetech.de/de/wordpress-keycloak-sso-plugin/
 * Description:       This plugin allows you to use Keycloak as a Single Sign-On provider for WordPress. It also supports adding Users to WordPress groups depending on their Keycloak roles.
 * Version:           0.0.1
 * Requires at least: 5.0
 * Requires PHP:      7.2
 * Author:            Luca Dünte
 * License:           MIT License
 * License URI:       https://opensource.org/license/mit
 */

 require_once plugin_dir_path(__FILE__) . 'includes/class.php';


 if (!function_exists('ksso_deploy_plugin')) {
    function ksso_deploy_plugin() {
        global $wpdb;

        $table_name = $wpdb->prefix . 'ksso_data';
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE $table_name (
            id TINYINT(1) NOT NULL,
            serverurl varchar(255) NOT NULL,
            realm varchar(255) NOT NULL,
            clientid varchar(255) NOT NULL,
            clientsecret text NOT NULL,
            PRIMARY KEY  (id)
        ) $charset_collate;";

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);

        add_option('ksso_db_version', '1.0');

        ksso_add_rewrite_rules();
        flush_rewrite_rules();
    }

    function ksso_add_rewrite_rules() {
        add_rewrite_rule('^sso/login/?$', 'index.php?sso_login=1', 'top');
    }

    function ksso_register_query_vars($vars) {
        $vars[] = 'sso_login';
        return $vars;
    }
    add_filter('query_vars', 'ksso_register_query_vars');
}


function ksso_request_jwt($code, $tokenservice, $clientid, $clientsecret) 
{
    try 
    {
        $params = array(
            'grant_type'    => 'authorization_code',
            'code'          => $code,
            'redirect_uri'  => site_url() . '/sso/login', 
            'client_id'     => $clientid, 
            'client_secret' => $clientsecret  
        );

        $tokenendpoint = $tokenservice . '/token';

        $response = wp_remote_post($tokenendpoint, array(
            'method' => 'POST',
            'body' => $params
        ));

        if (is_wp_error($response)) 
        {
            throw new Exception('Request failed: ' . $response->get_error_message());
        }

        $status_code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);

        if ($status_code == 200) 
        {
            $response_data = json_decode($body, true);

            if (isset($response_data['access_token'])) 
            {
                return $response_data['access_token']; 
            } 
            else 
            {
                throw new Exception('No access token found in response.');
            }
        }
        else 
        {
            throw new Exception("Error: Status - $status_code, Message - $body");
        }

    } 
    catch (Exception $e) 
    {
        throw new Exception('A critical Login error has occurred. Please inform the server administrator and report this error: ' . $e->getMessage());
    }
}



function ksso_decode_verify_read_jwt($jwt, $publickey, $session) 
{
    list($header, $payload, $signature) = explode('.', $jwt);

    $decoded_header = json_decode(base64_decode($header));
    $decoded_payload = json_decode(base64_decode($payload));

    if (!$decoded_header || !$decoded_payload) 
    {
        throw new Exception('Failed to decode JWT header or payload.');
    }

    if ($decoded_header->alg !== 'RS256') 
    {
        throw new Exception('Unexpected algorithm: ' . $decoded_header->alg);
    }

    $publickey = "-----BEGIN PUBLIC KEY-----\n" . wordwrap($publickey, 64, "\n", true) . "\n-----END PUBLIC KEY-----";
    $publickey_resource = openssl_pkey_get_public($publickey);

    if (!$publickey_resource) 
    {
        throw new Exception('Invalid public key format.');
    }

    $data_to_verify = $header . '.' . $payload;
    $signature_decoded = base64_decode(strtr($signature, '-_', '+/'));

    if (!$signature_decoded)
    {
        throw new Exception('Failed to decode the JWT signature.');
    }

    $verified = openssl_verify($data_to_verify, $signature_decoded, $publickey_resource, OPENSSL_ALGO_SHA256);

    if ($verified === 1) 
    {
        if (isset($decoded_payload->exp) ) 
        {
            $current_time = time();
            if ($decoded_payload->exp < $current_time) 
            {
                throw new Exception('Token has expired.');
            }
        } 
        else 
        {
            throw new Exception('Token has no expiration date.');
        }

        if (!isset($decoded_payload->session_state) || $decoded_payload->session_state !== $session) 
        {
            throw new Exception('Session state does not match.');
        }

        return $decoded_payload;
    } 
    elseif ($verified === 0) 
    {
        throw new Exception('Invalid signature.');
    } 
    else 
    {
        throw new Exception('Error verifying token: ' . openssl_error_string());
    }
}

function ksso_wordpress_user($userdata)
{
    try
    {
        $loginuserurl = false;

        $user = get_user_by('email', $userdata->email);

        if (!$user) 
        {
            $data = array(
                'user_login' => $userdata->preferred_username,
                'user_email' => $userdata->email,
                'user_pass' => wp_generate_password(),
                'first_name' => $userdata->given_name,
                'last_name' => $userdata->family_name,
            );
            $userID = wp_insert_user($data);

            if (is_wp_error($userID)) 
            {
                throw new Exception('Error creating user: ' . $userID->get_error_message());
            }

            $datausersub = array(
                'user_id' => $userID,
                'sub' => $userdata->sub,
            );

            $usermeta = add_user_meta($userID, 'sub', $userdata->sub, true);
            if (is_wp_error($usermeta)) 
            {
                throw new Exception('Error adding user meta (sub): ' . $usermeta->get_error_message());
            }
            return $userID;

        }
        else 
        {
            $usersub = get_user_meta($user->ID, 'sub', true);

            if ($usersub !== $userdata->sub && $user->user_email === $userdata->email) 
            {
                // Es melder sich ein Nutzer an, der wp_die selbe E-Mail-Adresse wie ein bereits bestehender Nutzer in der Wordpress Datenbank hat. Allerdings unterscheidet sich wp_die Sub-ID der beiden Nutzer. 
                // Das heißt, dass der alte Nutzer im Quellsystem gelöscht wurde und ein neuer Nutzer mit der selben E-Mail-Adresse angelegt wurde. In wp_diesem Fall wird der alte Nutzer 
                // in der Wordpress Datenbank gelöscht und der neue Nutzer wird angelegt.
                
                wp_delete_user($user->ID);

                if (is_wp_error($user)) 
                {
                    throw new Exception('Error deleting user (Sub doesnt match): ' . $user->get_error_message());
                }

                $data = array(
                    'user_login' => $userdata->preferred_username,
                    'user_email' => $userdata->email,
                    'user_pass' => wp_generate_password(),
                    'first_name' => $userdata->given_name,
                    'last_name' => $userdata->family_name,
                );
                $user = wp_insert_user($data);

                if (is_wp_error($user)) 
                {
                    throw new Exception('Error creating user: ' . $user->get_error_message());
                }
    
                $datausersub = array(
                    'user_id' => $user->ID,
                    'sub' => $userdata->sub,
                );
    
                $usermeta = add_user_meta($user, 'sub', $userdata->sub, true);
                if (is_wp_error($usermeta)) 
                {
                    throw new Exception('Error adding user meta (sub): ' . $usermeta->get_error_message());
                }

                return $user->ID;
            }
            else
            {
                $userID = $user->ID;
                $data = array(
                    'ID' => $userID,
                    'user_login' => $userdata->preferred_username,
                    'user_email' => $userdata->email,
                    'user_pass' => wp_generate_password(),
                    'first_name' => $userdata->given_name,
                    'last_name' => $userdata->family_name,
                );
                $user = wp_update_user($data);
    
                if (is_wp_error($user)) 
                {
                    throw new Exception('Error updating user: ' . $user->get_error_message());
                }

                return $userID;
            }
        }
    }
    catch (Exception $e) 
    {
        throw new Exception('A critical error has occurred. Please inform the server administrator and report this error: ' . $e->getMessage());
    }
}

function ksso_userlogin($userid)
{
    wp_set_current_user($userid);
    
    wp_set_auth_cookie($userid);
    
    do_action('wp_login', get_user_by('id', $userid)->user_login, get_user_by('id', $userid));
    
    wp_safe_redirect(home_url());

    exit;
}


// function ksso_add_user_to_db($userdata)
// {
//     global $wp_roles;
//     if (!isset($wp_roles)) 
//     {
//         $wp_roles = new WP_Roles();
//     }
//     $roles = $wp_roles->get_names();




// }

function ksso_handle_sso_login() 
{
    if (get_query_var('sso_login')) 
    {
        try 
        {
            $kcdata = new ksso_data();

            $iss = isset($_GET['iss']) ? sanitize_text_field($_GET['iss']) : null;
            $code = isset($_GET['code']) ? sanitize_text_field($_GET['code']) : null;
            $session = isset($_GET['session_state']) ? sanitize_text_field($_GET['session_state']) : null;

            if (!$iss) 
            {
                throw new Exception('No issuer received.');
            }

            if (!$code) 
            {
                throw new Exception('No authentication code received.');
            }

            if (!$session) 
            {
                throw new Exception('No session state received.');
            }

            if ($iss !== $kcdata->get_serverurl() . '/realms/' . $kcdata->get_realm())
            {
                throw new Exception('Issuer does not match.');
            }

            $access_token = ksso_request_jwt($code, $kcdata->get_tokenendpoint(), $kcdata->get_clientid(), $kcdata->get_clientsecret());
            
            $payload = ksso_decode_verify_read_jwt($access_token, $kcdata->get_publickey(), $session);

            $userid = ksso_wordpress_user($payload);

            ksso_userlogin($userid);

        } 
        catch (Exception $e) 
        {
            wp_die('A critical Login error has occurred. Please inform the server administrator and report this error: ' . $e->getMessage());
        }

        echo 'SSO Login erfolgreich! Authentifizierungscode: ' . print_r($payload, true);
        exit;
    }
}


register_activation_hook(__FILE__, 'ksso_deploy_plugin');
add_action('template_redirect', 'ksso_handle_sso_login');

