# php-security-api

This API, built in conformance to OWASP guidelines, is just a repository of decoupled components that correspond to most common web security patterns:

- authenticating users
	- via DB: authenticates users based on login form and DB through a data access object (DAO)
        - via XML: authenticates users based on <users> tag @ XML
        - via OAuth2: authenticates users based on OAuth2 client (eg: Facebook, Google)
- remembering authenticated state across requests:
	- via session: persists state into session
	- via remember me cookie: persists state into a cookie secured by a SynchronizerToken
	- via synchronizer token: for applications that must conform to REST principles and do not store state
	- via json web token: as an alternative to above
- authorizing users
	- via DB: authorizes user access to requested resource based on DB through a data access object (DAO)
	- via XML: authorizes user access to requested resource based on <routes> and <users> tags @ XML
- security validator tokens
	- json web token: reads, generates, validates a json web token
        - synchronizer token: reads, generates, validates a synchronizer token

Each of above is built on the principle of atomicity: root components should be loaded individually according to what project needs!

More information here:<br/>
http://www.lucinda-framework.com/web-security
