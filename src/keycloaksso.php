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
 require_once plugin_dir_path(__FILE__) . 'includes/functions.php';


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

        $table_name = $wpdb->prefix . 'ksso_roles';
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE $table_name (
            id TINYINT(1) NOT NULL,
            keycloak_role_name varchar(255) NOT NULL,
            wordpress_role_name varchar(255) NOT NULL,
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

function ksso_handle_sso_login() 
{
    if (get_query_var('sso_login')) 
    {
        try 
        {
            $kcdata = new ksso_data();
            $kcroles = new ksso_roles();

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

            $kcroles->user_add_rolemapping($userid, $payload);

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

