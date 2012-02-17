# RedmineDrupalAuth

An Ruby on Rails plugin of Redmine authentication source provider which allows users to log in [Redmine](http://www.redmine.org/) site with their username/password of [Drupal](http://drupal.org/) site.

- Based on [Alternative (custom) Authentication HowTo](http://www.redmine.org/projects/redmine/wiki/Alternativecustom_authentication_HowTo).
- Tested on Redmine 1.3.x and Drupal 7.x.

## Installation

Copy this directory to <code>redmine-path/vendor/plugins</code>.

Insert a record for the auth source like the following:

    INSERT INTO auth_sources
    (
      type, name,
      host, port, account, account_password, base_dn,
      attr_login, attr_firstname, attr_lastname, attr_mail,
      onthefly_register, tls
    )
    VALUES
    (
      'AuthSourceDrupal', 'Drupal',
      'localhost', '3306', 'db_id', 'db_passwd', 'mysql2:database_name'
      'name', 'firstname', 'lastname', 'mail',
      1, 0
    );

Copyright (c) 2012 Chulki Lee, released under the MIT license
