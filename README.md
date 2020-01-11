# Web Security API

This API implements common concerns of web security (authentication, authorization, state persistence, csrf prevention) using a mixture of declarative and programmatic approach:

- **[configuration](#configuration)**: setting up an XML file where web security is configured
- **[request](#setting-request-information)**: setting request information in a [Lucinda\WebSecurity\Request](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Request.php) instance
- **[getting results](#getting results)**: creating a [Lucinda\WebSecurity\Wrapper](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Wrapper.php) instance based on above and use it to get logged in user id, access token (for stateless apps) or csrf token (for form logins)

## Installation

This library is fully PSR-4 compliant and only requires PHP7.1+ interpreter and SimpleXML extension. For installation run:

```console
composer require lucinda/security
```

Create a file (eg: index.php) in project root with following code:

```php
require(__DIR__."/vendor/autoload.php");

$object = new Lucinda\WebSecurity\Wrapper(simplexml_load_file(XML_FILE_NAME), REQUEST, OAUTH2_DRIVERS);
```

Where:

- **XML_FILE_NAME**: (mandatory) holds path to XML file where web security is configured. See **[configuration](#configuration)** below!
- **REQUEST**: (mandatory) a [Lucinda\WebSecurity\Request](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Request.php) instance, encapsulating request information
- **OAUTH2_DRIVERS**: (optional) a list of [Lucinda\WebSecurity\Authentication\OAuth2\Driver](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Authentication/OAuth2/Driver.php) instances, encapsulating oauth2 vendors to login with

### Unit Tests

API has 100% unit test coverage, but uses [UnitTest API](https://github.com/aherne/unit-testing) instead of PHPUnit for greater flexibility. For tests and examples, check:

- [test.php](https://github.com/aherne/php-security-api/blob/v3.0.0/test.php): runs unit tests in console
- [unit-tests.xml](https://github.com/aherne/php-security-api/blob/v3.0.0/unit-tests.xml): sets up unit tests
- [tests](https://github.com/aherne/php-security-api/tree/v3.0.0/tests): unit tests for classes from [src](https://github.com/aherne/php-security-api/tree/v3.0.0/src) folder

## Configuration

To configure this API you must have a XML with following tags inside:

- **[security](#security)**: (mandatory) configures the api
- **[users](#users)**: (optional) required only if authentication is by XML (access control list)
- **[routes](#routes)**: (optional) required only if authorization is by XML (access control list)

### Security

Maximal syntax of this tag is:

```xml
<security dao_path="...">
    <csrf secret="..." expiration="..."/>
    <persistence>
        <session parameter_name="..." expiration="..." is_http_only="..." is_https_only="..." ignore_ip="..." handler="..."/>
        <remember_me secret="..." parameter_name="..."  expiration="..." is_http_only="..." is_https_only="..."/>
        <synchronizer_token secret="..." expiration="..." regeneration="..."/>
        <json_web_token secret="..." expiration="..." regeneration="..."/>
    </persistence>
    <authentication>
        <form dao="..." throttler="...">
			<login page="..." target="..." parameter_username="..." parameter_password="..."  parameter_rememberMe="..." />
			<logout page="..." target="..."/>
		</form>
		<oauth2 dao="..." target="..." login="..." logout="..."/>
    </authentication>
    <authorization>
        <by_dao page_dao="..." user_dao="..." logged_in_callback="..." logged_out_callback="..."/>
        <by_route logged_in_callback="..." logged_out_callback="..."/>
    </authorization>
</security>
```

Where:

- **security**: (mandatory) holds global web security policies. 
    - *dao_path*: location to DAO classes (required if authentication/authorization use database)    
    - **csrf**: (mandatory) holds settings necessary to produce an anti-CSRF token (useful to sign authentication with)
        - *secret*: (mandatory) password to use in encrypting csrf token (use: [Lucinda\WebSecurity\Token\SaltGenerator](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Token/SaltGenerator.php))
        - *expiration*: (optional) seconds until token expires. If not set, token will expire in 10 minutes.
    - **persistence** (mandatory) holds one or more mechanisms useful to preserve logged in state across requests (at least one is mandatory!)
        - **session**: (optional) configures persistence of logged in state by HTTP session
            - *parameter_name*: (optional) name of $_SESSION parameter that will store logged in state. If not set, "uid" is assumed.
            - *expiration*: (optional) seconds until session expires. If not set, session will expire as server-default.
            - *is_http_only*: (optional) whether or not to set session cookie as HttpOnly (can be 0 or 1; 0 is default).
            - *is_https_only*: (optional) whether or not to set session cookie as HTTPS only (can be 0 or 1; 0 is default).
            - *handler*: (optional) name of class (incl. namespace or relative path) extending [SessionHandlerInterface](https://www.php.net/manual/en/class.sessionhandlerinterface.php) to which session handling will be delegated to. 
        - **remember_me**: (optional) configures persistence of logged in state by HTTP remember me cookie
            - *secret*: (mandatory) password to use in encrypting cookie (use: [Lucinda\WebSecurity\Token\SaltGenerator](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Token/SaltGenerator.php))
            - *parameter_name*: (optional) name of $_COOKIE parameter that will store logged in state. If not set, "uid" is assumed.
            - *expiration*: (optional) seconds until cookie expires. If not set, cookie will expire in one day.
            - *is_http_only*: (optional) whether or not to set cookie as HttpOnly (can be 0 or 1; 0 is default).
            - *is_https_only*: (optional) whether or not to set cookie as HTTPS only (can be 0 or 1; 0 is default).
        - **synchronizer_token**: (optional) configures persistence of logged in state by signing every request with a synchronizer token
            - *secret*: (mandatory) password to use in encrypting token (use: [Lucinda\WebSecurity\Token\SaltGenerator](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Token/SaltGenerator.php))
            - *expiration*: (optional) seconds until token expires. If not set, token will expire in 1 hour.
            - *regeneration*: (optional) seconds from the moment token was created until it needs to regenerate on continuous usage. If not set, token will be regenerated in 1 minute.
        - **json_web_token**: (optional) configures persistence of logged in state by signing every request with a json web token
            - *secret*: (mandatory) password to use in encrypting token (use: [Lucinda\WebSecurity\Token\SaltGenerator](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Token/SaltGenerator.php))
            - *expiration*: (optional) seconds until token expires. If not set, token will expire in 1 hour.
            - *regeneration*: (optional) seconds from the moment token was created until it needs to regenerate on continuous usage. If not set, token will be regenerated in 1 minute.
    - **authentication**: (mandatory) holds one or more mechanisms to authenticate (at least one is mandatory!)
        - **form**: (optional) configures authentication via form. If no *dao* attribute is set, authentication is done via XML and [users](#users) tag is required!
            - *dao*: (optional) name of class (incl. namespace or subpath) extending [Lucinda\WebSecurity\Authentication\DAO\UserAuthenticationDAO](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Authentication/DAO/UserAuthenticationDAO.php) that performs form authentication in database, found in folder set by *dao_path* attribute above. [1]
            - *throttler*: (optional) name of class (incl. namespace or subpath) extending [Lucinda\WebSecurity\Authentication\Form\LoginThrottler](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Authentication/Form/LoginThrottler.php) that performs login throttling prevention, found in folder set by *dao_path* attribute above
            - **login**: (optional) configures login
                - *page*: (optional) page that performs login operation (all requests to this page will pass through this filter), also one to redirect back if login is unsuccessful. If none, then "login" is implicitly used.
                - *target*: (optional) destination page after successful login. If none, then "index" is implicitly used.
                - *parameter_username*: (optional) name of $_POST parameter username will be submitted as. If none, then "username" is implicitly used.
                - *parameter_password*: (optional) name of $_POST parameter password will be submitted as. If none, then "password" is implicitly used.
                - *parameter_rememberMe*: (optional) name of $_POST parameter that activates "remember me" option (value can be 0 or 1). If none, then "remember_me" is implicitly used.
            - **logout**: (optional) configures logout
                - *page*: (optional) page that performs logout operation (all requests to this page will pass through this filter). If none, then "logout" is implicitly used.
                - *target*: (optional) destination page after successful or unsuccessful logout. If none, then "login" is implicitly used.
        - **oauth2**: (optional) configures authentication via oauth2 provider
            - *dao*: (mandatory) name of class (incl. namespace or subpath) extending [Lucinda\WebSecurity\Authentication\OAuth2\VendorAuthenticationDAO](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Authentication/OAuth2/VendorAuthenticationDAO.php) that saves results of authentication in database, found in folder set by *dao_path* attribute above
            - *target*: (optional) destination page after successful login. If none, then "index" is implicitly used.
            - *login*: (optional) generic page where login by provider option is available. If none, then "login" is implicitly used. 
            - *logout*: (optional) page that performs logout operation. If none, then "logout" is implicitly used.
    - **authorization**: (mandatory) holds a single mechanism to authorize requests (at least one is mandatory!)
        - **by_dao**: (optional) configures authorization by database
            - *page_dao*: (mandatory) name of class (incl. namespace or subpath) extending [Lucinda\WebSecurity\Authorization\DAO\UserAuthorizationDAO](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Authorization/DAO/UserAuthorizationDAO.php) that checks user rights in database, found in folder set by *dao_path* attribute above
            - *user_dao*: (mandatory) name of class (incl. namespace or subpath) extending [Lucinda\WebSecurity\Authorization\DAO\PageAuthorizationDAO](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Authorization/DAO/PageAuthorizationDAO.php) that checks page rights in database, found in folder set by *dao_path* attribute above
            - *logged_in_callback*: (optional) callback page for authenticated users when authorization fails. If none, then "index" is implicitly used.
            - *logged_out_callback*: (optional) callback page for guest users when authorization fails. If none, then "login" is implicitly used.
        - **by_route**: (optional) configures authorization by XML, in which case [routes](#routes) tag is required. [1]
            - *logged_in_callback*: (optional) callback page for authenticated users when authorization fails. If none, then "index" is implicitly used.
            - *logged_out_callback*: (optional) callback page for guest users when authorization fails. If none, then "login" is implicitly used.

Notes:
(1) If authorization is **by_route**, **authentication** is **form** with a *dao* attribute, then class referenced there must also implement [Lucinda\WebSecurity\Authorization\PageRoles](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Authorization/PageRoles.php)

### Users

This tag is required if XML authentication (**form** tag is present and has no *dao* attribute) + authorization (**by_route** tag is present) are used. Syntax is:


```xml
<users>
    <user id="..." username="..." password="..." roles="..."/>
    ...
</security>
```

Where:

- **users**: (mandatory) holds list of site users, each identified by a **user** tag
    - **user**: (mandatory) holds information about a single user
        - *id*: (mandatory) holds unique user identifier (eg: 1)
        - *username*: (optional) holds user's username (eg: john_doe). Mandatory for XML authentication!
        - *password*: (optional) holds user's password hashed using [password_hash](https://www.php.net/manual/en/function.password-hash.php) (eg: value of ```php password_hash("doe", PASSWORD_BCRYPT) ```).   Mandatory for XML authentication!
        - *roles*: (optional) holds list of roles user belongs to, separated by commas (eg: USERS, ADMINISTRATORS). Mandatory for XML authentication+authorization

If no user is detected in list above, GUEST role is automatically assumed!

### Routes

This tag is required if XML authorization (**by_route** tag is present) is used. Syntax is:


```xml
<routes roles="...">
    <route url="..." roles="..."/>
    ...
</routes>
```

Where:

- **routes**: (mandatory) holds list of site routes, each identified by a **route** tag
    - *roles*: (mandatory) holds list of roles all pages are assumed to belong by default to, separated by commas (eg: GUEST)
    - **route**: (mandatory) holds policies about a specific route
        - *url*: (mandatory) page relative url (eg: administration)
        - *roles*: (mandatory) holds list of roles page is associated to, separated by commas (eg: USERS, ADMINISTRATORS)

## Setting request information

Both authentication and authorization require knowledge of request to be handled. All of this is encapsulated by a a [Lucinda\WebSecurity\Request](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Request.php) instance with following public methods:


| Method | Arguments | Returns | Description |
| --- | --- | --- | --- |
| setIpAddress | string $value | void | Sets ip address used by client (eg: value of $_SERVER["REMOTE_ADDR"]) |
| setContextPath | string $value | void | Sets context path that prefixes page requested by client (eg: prefix of $_SERVER["REQUEST_URI"]) |
| setUri | string $value | void | Sets page/resource requested by client (eg: suffix of $_SERVER["REQUEST_URI"])  |
| setMethod | string $value | void | Sets HTTP method used by client in page request (eg: value of $_SERVER["REQUEST_METHOD"]) |
| setParameters | array $value | void | Sets parameters sent by client as GET/POST along with request (eg: value of $_REQUEST) |
| setAccessToken | string $value | void | Sets access token detected from client headers for stateless login (eg:  suffix of $_SERVER["HTTP_AUTHORIZATION"]) |