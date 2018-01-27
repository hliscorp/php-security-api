# php-security-api

This API, built in conformance to OWASP guidelines, is just a repository of decoupled components that correspond to most common web security patterns:

<ul>
	<li>authenticating users
		<ul>
			<li>via DB: authenticates users based on login form and DB through a data access object (DAO)</li>
			<li>via XML: authenticates users based on tags @ XML</li>
			<li>via OAuth2: authenticates users based on OAuth2 client (eg: Facebook, Google)</li>
		</ul>
	</li>
	<li>remembering authenticated state across requests:
		<ul>
			<li>via session: persists state into session</li>
			<li>via remember me cookie: persists state into a cookie secured by a synchronizer token</li>
			<li>via synchronizer token: for applications that must conform to REST principles and do not store state</li>
			<li>via json web token: as an alternative to above</li>
		</ul>
	</li>
	<li>authorizing users
		<ul>
			<li>via DB: authorizes user access to requested resource based on DB through a data access object (DAO)</li>
			<li>via XML: authorizes user access to requested resource based on tags @ XML</li>
		</ul>
	</li>
	<li>security validator tokens
		<ul>
			<li>json web token: reads, generates, validates a json web token</li>
			<li>synchronizer token: reads, generates, validates a synchronizer token</li>
		</ul>
	</li>

</ul>

Each of above is built on the principle of atomicity: root components should be loaded individually according to what project needs!

More information here:<br/>
http://www.lucinda-framework.com/web-security
