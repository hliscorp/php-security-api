# php-security-api
Collection of decoupled components for PHP applications implementing web security patterns:

**Authentication**: the process that checks user's identity. This library implements:

- *FormAuthentication*:  implements authentication via forms, persisting logged in state into PersistenceDrivers

**Authorization**: the process that checks user's access to a requested resource. This library implements:

- *DAOAuthorization*: implements authorization via DAOs that encapsulate rights checking for users and resources.

**Persistence**: the process that retains (authorized) state between requests. This library implements:

- *PersistenceDriver*: defines the blueprints of persistence mechanisms
- *SessionPersistenceDriver*: implements persistence of authorized state via sessions, secured against replay
- *RememberMePersistenceDriver*: implements persistence of authorized state via cookies, crypted and secured against replay
- *TokenPersistenceDriver*: implements saving authorized state via synchronizer tokens, crypted and secured against replay. Useful for single-page applications that use MVC frameworks on front-end and RESTful APIs on backend.

**Tokens**: used to generate access tokens. This library implements:

- *SynchronizerToken*: defines a crypted state mechanism that acts like an anti-CSRF guard as well as a simple and powerful way to maintain state for single-page-applications (such as those using Angular JS).
- *JsonWebToken*: defines authentication and authorization via JSON web tokens (see more: https://en.wikipedia.org/wiki/JSON_Web_Token). NOTE: this is not loaded by default when library is included!