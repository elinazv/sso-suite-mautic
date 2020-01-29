# home-page

This package makes it simple to integrate 3 applications for Single Sign On:
- Onelogin as Identity Provider
- SuiteCRM
- Mautic

##Functionality
- After login on start page with your onelogin account you are already logged in by SuiteCRM and Mautic
- After registration (Sign Up) you are registered by:
    - Onelogin
    - SuiteCRM
    - Mautic
    
##Instructions
- Register an account by onelogin
- You may want to create at first a developer account by Onelogin
- Such account is not limited by time
- Allows you to have 10 users and 3 applications

##Onelogin
- Register 3 applications in Onelogin
    - Home with SAML Test Connector (IdP w/attr)
    - SuiteCRM with SugarCRM Connector
    - Mautic with SAML Test Connector (IdP w/attr)

- After registration you have for each application:
    - issuer url (idp or identity provider url),
    e.g. https://app.onelogin.com/saml/metadata/123
    - sso url (singleSignonService),
    e.g. https://mydomain.onelogin.com/trust/saml2/http-post/sso/123
    - slo url (singleSingoutService),
    e.g. https://mydomain.onelogin.com/trust/saml2/http-redirect/slo/123
    
##API Credentials
- You should also get client id and client secret for API for each application
    - For onelogin you get them after logging in with admin account at Developers > API Credentials
    - Please get a look into documentation for SuiteCRM and Mautic for getting API Credentials
    
Now you are ready for configuring settings.php.
You have to substitute words in capital letters and brackets like:
- <SUITECRM_BASE_URL>

##Home database for Oauth2 refresh tokens and cookies
- Create a database with following scheme:

CREATE TABLE `cookies` (
  `id` varchar(36) NOT NULL,
  `name` varchar(200) NOT NULL,
  `value` varchar(200) NOT NULL,
  `source` enum('mautic','suite') DEFAULT NULL,
  `created_at` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `cookie_source` (`name`,`value`,`source`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE `oauth2_tokens` (
  `id` varchar(36) NOT NULL,
  `access_token` varchar(8192) NOT NULL,
  `refresh_token` varchar(255) DEFAULT NULL,
  `account_id` int(11) DEFAULT NULL,
  `token_type` varchar(255) DEFAULT NULL,
  `access_token_expires` bigint(20) NOT NULL,
  `created_at` bigint(20) NOT NULL,
  `provider` enum('mautic','suite','onelogin') NOT NULL,
  PRIMARY KEY (`id`),
  KEY `access_token_expires` (`access_token_expires`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1; 

- Fill database parameters (dbname, host, user, password) in settings.php

Have fun!
Don't hesitate to ask me questions, if any by mail:

elinazv@yahoo.com
