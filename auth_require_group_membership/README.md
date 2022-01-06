# auth_require_group_membership
RoundCube plugin for LDAP authentication with group membership requirement
Tested with 1.1.3 stable release

I have RC installation with 2 interfaces: intranet http for all users and public https for members of certain security group only, and IMAP server with LDAP authentication
This plugin allows you to grant access for all valid users from within local network and require user to be a member of security group to access webmail outside company

All parameters in config file is self-explanatory

Before using it, you have to configure LDAP http://trac.roundcube.net/wiki/Howto_Config/Ldap#ConfiguringRoundcube

This plugin also allows you 
* pre-filter username with regex to check if it includes only allowed chars
* log failed attempts with IP and timestamp to separate file
* check is user exists in AD before IMAP auth attempt

```php
$config['ldap_public']['local_users'] = array(
    'name' => 'All users',
    'encoding' => 'utf8', // added
    'hosts' => array ('ad_dc_ip'),
    'sizelimit' => 6000,
    'port' => 3268, // 389, # See comments below
    'use_tls' => false,
    'user_specific' => false,
    'base_dn' => 'DC=org,DC=ad,DC=local',
    'bind_dn' => 'CN=ldapuser,CN=users,DC=org,DC=ad,DC=local',
    'bind_pass' => 'pass',
    'auth_method'=>'DIGEST-MD5',
    'auth_cn'=>'ldapuser',
    'auth_cid'=>'',
    'writable' => false,
    'ldap_version' => 3,
    'search_fields' => array ('mail','displayName','sAMAccountName'),
    'name_field' => 'displayName',
    'email_field' => 'mail',
    'surname_field' => '',
    'firstname_field' => '',
    'sort' => 'displayName',
    'scope' => 'sub',
    'filter' => '(&(mail=*)(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
    'global_search' => true,
    'fuzzy_search' => true
);
```

also in /vendor/kolab/net_ldap3/lib/Net/LDAP3.php inside comment block
```php
public function sasl_bind($authc = '', $pass = '', $authz = null) 
/*
if (!empty($authz)) {
$authz = 'u:' . $authz;
}
*/
```