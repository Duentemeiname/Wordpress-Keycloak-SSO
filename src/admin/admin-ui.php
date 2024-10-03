<?php

add_action('admin_menu', 'ksso_plugin_create_menu');

function ksso_plugin_create_menu() {
    add_menu_page(
        'Keycloak Single Sign On Settings',         
        'Keycloak SSO',                  
        'manage_options',        
        'ksso-plugin',           
        'ksso_settings_page',    
        'dashicons-admin-generic', 
        110                       
    );
}

function ksso_settings_page() 
{
    if (isset($_POST['ksso_save_settings'])) {
        $serverurl = sanitize_text_field($_POST['ksso_serverurl']);
        $realm = sanitize_text_field($_POST['ksso_realm']);
        $clientid = sanitize_text_field($_POST['ksso_clientid']);
        $clientsecret = sanitize_text_field($_POST['ksso_clientsecret']);

        $ksso_data = new ksso_data($serverurl, $realm, $clientid, $clientsecret);
    }

    if (isset($_POST['ksso_save_role_mapping'])) 
    {
        $kc_role = sanitize_text_field($_POST['ksso_kc_role']);
        $wp_role = sanitize_text_field($_POST['ksso_wp_role']);

        $ksso_roles = new ksso_roles($kc_role, $wp_role);
    } 
    elseif (isset($_POST['delete_role_mapping'])) 
    {
        $role_mapping_id = intval($_POST['role_mapping_id']);
        $ksso_roles = new ksso_roles();
        $ksso_roles->delete_rolemapping($role_mapping_id);
    } 
    else 
    {
        $ksso_roles = new ksso_roles();
    }

    $ksso_data = new ksso_data();
    $serverurl = esc_attr($ksso_data->get_serverurl());
    $realm = esc_attr($ksso_data->get_realm());
    $clientid = esc_attr($ksso_data->get_clientid());
    $clientsecret = esc_attr($ksso_data->get_clientsecret());

    $ksso_roles = new ksso_roles();
    $role_mappings = $ksso_roles->get_roles();
    $available_roles = $ksso_roles->get_available_wordpress_roles(); 

    ?>
    <div class="wrap">
        <h1>Keycloak Single Sign On Settings</h1>
        <h2>Basic Settings</h2>
        <p>Here you configure the basics so that WordPress can redirect the user to your Keycloak instance and request the JWT.</p>
        <form method="post" action="">
            <table class="form-table">
                <tr>
                    <th scope="row"><label for="ksso_serverurl">Server URL</label></th>
                    <td><input type="text" name="ksso_serverurl" id="ksso_serverurl" value="<?php echo $serverurl; ?>" class="regular-text" /></td>
                </tr>
                <tr>
                    <th scope="row"><label for="ksso_realm">Realm</label></th>
                    <td><input type="text" name="ksso_realm" id="ksso_realm" value="<?php echo $realm; ?>" class="regular-text" /></td>
                </tr>
                <tr>
                    <th scope="row"><label for="ksso_clientid">Client ID</label></th>
                    <td><input type="text" name="ksso_clientid" id="ksso_clientid" value="<?php echo $clientid; ?>" class="regular-text" /></td>
                </tr>
                <tr>
                    <th scope="row"><label for="ksso_clientsecret">Client Secret</label></th>
                    <td>
                        <input type="password" name="ksso_clientsecret" id="ksso_clientsecret" value="<?php echo $clientsecret; ?>" class="regular-text" />
                        <button type="button" id="toggle-secret" class="button">Anzeigen</button>
                    </td>
                </tr>
            </table>
            <input type="submit" name="ksso_save_settings" class="button button-primary" value="Speichern" />
        </form>

        <hr>
        <h1>Advanced Settings - Roles</h1>
        <p>Note: These settings are optional. Here you can set which role a user gets in WordPress, depending on their Keycloak role.</p>
        <form method="post" action="">
            <h2>Keycloak to WordPress Role Mapping</h2>
            <table class="form-table">
                <tr>
                    <th><label for="ksso_kc_role">Keycloak Role</label></th>
                    <td><input type="text" name="ksso_kc_role" id="ksso_kc_role" class="regular-text"></td>
                </tr>
                <tr>
                    <th><label for="ksso_wp_role">WordPress Role</label></th>
                    <td>
                        <select name="ksso_wp_role" id="ksso_wp_role">
                            <?php foreach ($available_roles as $role_key => $role): ?>
                                <option value="<?php echo esc_attr($role_key); ?>"><?php echo esc_html($role['name']); ?></option>
                            <?php endforeach; ?>
                        </select>
                    </td>
                </tr>
            </table>
            <p><input type="submit" name="ksso_save_role_mapping" class="button button-primary" value="Save Role Mapping"></p>
        </form>

        <h2>Current Role Mappings</h2>
        <table class="widefat fixed">
            <thead>
                <tr>
                    <th>Keycloak Role</th>
                    <th>WordPress Role</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                <?php if (!empty($role_mappings)): ?>
                    <?php foreach ($role_mappings as $kc_role => $wp_role): ?>
                        <tr>
                            <td><?php echo esc_html($kc_role); ?></td>
                            <td><?php echo esc_html($available_roles[$wp_role]['name']); ?></td>
                            <td>
                                <form method="post" action="">
                                    <input type="hidden" name="role_mapping_id" value="<?php echo esc_attr($kc_role); ?>">
                                    <input type="submit" name="delete_role_mapping" class="button button-secondary" value="Delete">
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                <?php else: ?>
                    <tr>
                        <td colspan="3">No Role Mappings found</td>
                    </tr>
                <?php endif; ?>
            </tbody>
        </table>
    </div>

    <script>
        document.getElementById('toggle-secret').addEventListener('click', function() {
            var secretField = document.getElementById('ksso_clientsecret');
            if (secretField.type === 'password') {
                secretField.type = 'text';
            } else {
                secretField.type = 'password';
            }
        });
    </script>
    <?php
}
