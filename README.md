# Lightweight authentication library

[![Build Status](https://travis-ci.org/gyselroth/micro-auth.svg?branch=master)](https://travis-ci.org/gyselroth/micro-auth)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/gyselroth/micro-auth/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/gyselroth/micro-auth/?branch=master)
[![Latest Stable Version](https://img.shields.io/packagist/v/gyselroth/micro-auth.svg)](https://packagist.org/packages/gyselroth/micro-auth)
[![GitHub release](https://img.shields.io/github/release/gyselroth/micro-auth.svg)](https://github.com/gyselroth/micro-auth/releases)
[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/gyselroth/micro-auth/master/LICENSE)

## Description
This is a lightweight authentication library. It is adapter based and comes with support for LDAP and OpenID-connect. 
It can handle multiple adapter of the same or different types. 
This library contains no storage mechanism. If you wish to store the authentication you need to store the identity object in your sessesion storage.

## Requirements
The library is only >= PHP7.1 compatible.

## Download
The package is available at packagist: https://packagist.org/packages/gyselroth/micro-auth

To install the package via composer execute:
```
composer require gyselroth/micro-auth
```

## Documentation

### Simple example usage

Create authentication instance and inject an LDAP and OpenID-connect adapter:

```php
use Micro\Auth;

$logger = new \My\Psr\Logger()
$auth = new Auth\Auth(\Psr\Log\LoggerInterface $logger);
$auth->injectAdapter(new Auth\Adapter\Basic\Ldap(new Auth\Ldap([
    'uri' => 'ldap://myldap.local:398',
    'binddn' => 'cn=admin,dc=test,dc=com',
    'bindpw' => '1234',
    'basedn' => 'dc=test,dc=com',
    'tls' => true
]), $logger, [
    'account_filter' => '(&(objectClass=posixAccount)(uid=%s))'
]), 'my_ldap_server');

$auth->injectAdapter(new Auth\Adapter\Oidc([
    'provider_url' => 'https://accounts.google.com',
    'identity_attribute' => 'email'
], $logger), 'google_oidc_server');

if($auth->requireOne()) {
    $identity = $auth->getIdentity();
    printf('Hello %s', $identity->getIdentifier());
} else {
    //Authentication failed
}
```

### Define attribute map

So far so good but usually just authenticate is not enaugh, mostly you like to request user attributes of a given identity.
Let us create an attribute map for our ldap server `my_ldap_server`.

```php
use Micro\Auth;

$auth->injectAdapter(new Auth\Adapter\Basic\Ldap(new Auth\Ldap([
    'uri' => 'ldap://myldap.local:398',
    'binddn' => 'cn=admin,dc=test,dc=com',
    'bindpw' => '1234',
    'basedn' => 'dc=test,dc=com',
    'tls' => true
]), $logger, [
    'account_filter' => '(&(objectClass=posixAccount)(uid=%s))',
    'attribute_map' => [
        'firstname' => [
            'attr' => 'firstname',
            'type' => 'string',
        ],
        'lastname' => [
            'attr' => 'surname',
            'type' => 'string',
        ],
        'mail' => [
            'attr' => 'mail',
            'type' => 'string'
        ]
    ]
]), 'my_ldap_server');

if($auth->requireOne()) {
    $attributes = $auth->getIdentity()->getAttributes();
    var_dump($attributes);
} else {
    //Authentication failed
}
```

Given that, you can define an attribute map for each authentication adapter and map all attributes to the same attribute names you would like to use.
#