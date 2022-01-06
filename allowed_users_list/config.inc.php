<?php

// The id of the address book to use to automatically set a
// user's full name in their new identity. (This should be an
// string, which refers to the $config['ldap_public'] array.)
$config['allowed_users_list_file'] = 'allowed_users.csv';

$config['allowed_users_list_addressbook'] = 'local_users';
// required group distinguishedName
$config['allowed_users_list_required_dn'] = 'CN=AllowPublicWebMail,CN=Users,DC=domain,DC=local';
// filename (in RC/log folder) or leave empty for logging debug info
$config['allowed_users_list_debug_log'] = 'allowed_users_list.log';


