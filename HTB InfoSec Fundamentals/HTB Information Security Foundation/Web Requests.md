* ## HyperText Transfer Protocol (HTTP)
	* [HTTP](https://tools.ietf.org/html/rfc2616) is an application-level protocol used to access the World Wide Web resources. The term `hypertext` stands for text containing links to other resources and text that the readers can easily interpret.
	* HTTP communication consists of a client and a server, where the client requests the server for a resource. The server processes the requests and returns the requested resource. The default port for HTTP communication is port `80`, though this can be changed to any other port, depending on the web server configuration.
	* The same requests are utilized when we use the internet to visit different websites. We enter a `Fully Qualified Domain Name` (`FQDN`) as a `Uniform Resource Locator` (`URL`) to reach the desired website, like [www.hackthebox.com](http://www.hackthebox.com/).
	* **URL**
		* Resources over HTTP are accessed via a `URL`, which offers many more specifications than simply specifying a website we want to visit. Let's look at the structure of a URL: ![url_structure](https://academy.hackthebox.com/storage/modules/35/url_structure.png)
		* Here is what each component stands for:
			* |`Scheme`|`http://` `https://`|This is used to identify the protocol being accessed by the client, and ends with a colon and a double slash (`://`)
			* |`User Info`|`admin:password@`|This is an optional component that contains the credentials (separated by a colon `:`) used to authenticate to the host, and is separated from the host with an at sign (`@`)
			* |`Host`|`inlanefreight.com`|The host signifies the resource location. This can be a hostname or an IP address
			* |`Port`|`:80`|The `Port` is separated from the `Host` by a colon (`:`). If no port is specified, `http` schemes default to port `80` and `https` default to port `443`
			* |`Path`|`/dashboard.php`|This points to the resource being accessed, which can be a file or a folder. If there is no path specified, the server returns the default index (e.g. `index.html`).
			* |`Query String`|`?login=true`|The query string starts with a question mark (`?`), and consists of a parameter (e.g. `login`) and a value (e.g. `true`). Multiple parameters can be separated by an ampersand (`&`).
			* |`Fragments`|`#status`|Fragments are processed by the browsers on the client-side to locate sections within the primary resource (e.g. a header or section on the page).
	* **HTTP Flow**
		* ![[Pasted image 20231221110123.png]]
	* **cURL**
		* [cURL](https://curl.haxx.se/) (client URL) is a command-line tool and library that primarily supports HTTP along with many other protocols. This makes it a good candidate for scripts as well as automation, making it essential for sending various types of web requests from the command line, which is necessary for many types of web penetration tests.
			* `curl inlanefrieght.com`
		* We may also use cURL to download a page or a file and output the content into a file using the `-O` flag. If we want to specify the output file name, we can use the `-o` flag and specify the name. Otherwise, we can use `-O` and cURL will use the remote file name, as follows:
			* `curl -O inlanefreight.com/index.html`
		* As we can see, the output was not printed this time but rather saved into `index.html`. We noticed that cURL still printed some status while processing the request. We can silent the status with the `-s` flag, as follows:
			* `curl -s -O inlanefreight.com/index.html`
* ## HyperText Transfer Protocol Secure (HTTPS)
	* [HTTPS (HTTP Secure) protocol](https://tools.ietf.org/html/rfc2660) created so all communications are transferred in an encrypted format, so even if a third party does intercept the request, they would not be able to extract the data out of it. For this reason, HTTPS has become the mainstream scheme for websites on the internet, and HTTP is being phased out, and soon most web browsers will not allow visiting HTTP websites.
	* **HTTPS Flow**
		* ![[Pasted image 20231221110647.png]]
		* If we type `http://` instead of `https://` to visit a website that enforces HTTPS, the browser attempts to resolve the domain and redirects the user to the webserver hosting the target website. A request is sent to port `80` first, which is the unencrypted HTTP protocol. The server detects this and redirects the client to secure HTTPS port `443` instead. This is done via the `301 Moved Permanently` response code, which we will discuss in an upcoming section.
		* Next, the client (web browser) sends a "client hello" packet, giving information about itself. After this, the server replies with "server hello", followed by a [key exchange](https://en.wikipedia.org/wiki/Key_exchange) to exchange SSL certificates. The client verifies the key/certificate and sends one of its own. After this, an encrypted [handshake](https://www.cloudflare.com/learning/ssl/what-happens-in-a-tls-handshake) is initiated to confirm whether the encryption and transfer are working correctly.
		* **Note:** Depending on the circumstances, an attacker may be able to perform an ==HTTP downgrade attack==, which downgrades HTTPS communication to HTTP, making the data transferred in clear-text. This is done by setting up a Man-In-The-Middle (MITM) proxy to transfer all traffic through the attacker's host without the user's knowledge. However, most modern browsers, servers, and web applications protect against this attack.
	* **cURL for HTTPS**
		* cURL should automatically handle all HTTPS communication standards and perform a secure handshake and then encrypt and decrypt data automatically.
		* However, if we ever contact a website with an invalid SSL certificate or an outdated one, then cURL by default would not proceed with the communication to protect against the earlier mentioned MITM attacks:
			* `curl https://inlanefreight.com`
		* We may face such an issue when testing a local web application or with a web application hosted for practice purposes, as such web applications may not yet have implemented a valid SSL certificate. To skip the certificate check with cURL, we can use the `-k` flag:
			* `curl -k https://inlanefreight.com`
* ## HTTP Requests and Responses
	* HTTP communications mainly consist of an HTTP request and an HTTP response. An HTTP request is made by the client (e.g. cURL/browser), and is processed by the server (e.g. web server). The requests contain all of the details we require from the server, including the resource (e.g. URL, path, parameters), any request data, headers or options we specify, and many other options we will discuss throughout this module.
	* **HTTP Request**
		* ![[Pasted image 20231221112057.png]]
		* image above shows an HTTP GET request to the URL: `http://inlanefreight.com/users/login.html`
		* The first line of any HTTP request contains three main fields 'separated by spaces':
			* `Method` (e.g. `GET`) - The HTTP method or verb, which specifies the type of action to perform.
			* `Path` (e.g. `/users/login.html`) - The path to the resource being accessed. This field can also be suffixed with a query string (e.g. ?username=user).
			* `Version` (e.g. `HTTP/1.1`) - The third and final field is used to denote the HTTP version.
		* The next set of lines contain HTTP header value pairs, like `Host`, `User-Agent`, `Cookie`, and many other possible headers. These headers are used to specify various attributes of a request. The headers are terminated with a new line, which is necessary for the server to validate the request. Finally, a request may end with the request body and data.
		* **Note:** HTTP version 1.X sends requests as clear-text, and uses a new-line character to separate different fields and different requests. HTTP version 2.X, on the other hand, sends requests as binary data in a dictionary form.
	* **HTTP Response**
		* ![[Pasted image 20231221112841.png]]
		* The first line of an HTTP response contains two fields separated by spaces. The first being the `HTTP version` (e.g. `HTTP/1.1`), and the second denotes the `HTTP response code` (e.g. `200 OK`).
		* Finally, the response may end with a response body, which is separated by a new line after the headers. The response body is usually defined as `HTML` code. However, it can also respond with other code types such as `JSON`, website resources such as images, style sheets or scripts, or even a document such as a PDF document hosted on the webserver.
	* **cURL**
		* cURL also allows us to preview the full HTTP request and the full HTTP response, which can become very handy when performing web penetration tests or writing exploits. To view the full HTTP request and response, we can simply add the `-v` verbose flag to our earlier commands, and it should print both the request and response:
			* `curl inlanefreight.com -v`
	* **Browser DevTools**
		* Most modern web browsers come with built-in developer tools (`DevTools`), which are mainly intended for developers to test their web applications. However, as web penetration testers, these tools can be a vital asset in any web assessment we perform, as a browser (and its DevTools) are among the assets we are most likely to have in every web assessment exercise.
		* To open the browser devtools in either Chrome or Firefox, we can click [`CTRL+SHIFT+I`] or simply click [`F12`]. The devtools contain multiple tabs, each of which has its own use. We will mostly be focusing on the `Network` tab in this module, as it is responsible for web requests.
* ## HTTP Headers
	* Headers can have one or multiple values, appended after the header name and separated by a colon. We can divide headers into the following categories:
		1. `General Headers`
			* [General headers](https://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html) are used in both HTTP requests and responses. They are contextual and are used to `describe the message rather than its contents`.
				* Date
				* Connection
		2. `Entity Headers`
			* Similar to general headers, [Entity Headers](https://www.w3.org/Protocols/rfc2616/rfc2616-sec7.html) can be `common to both the request and response`. These headers are used to `describe the content` (entity) transferred by a message. They are usually found in responses and POST or PUT requests.
				* Content-Type
				* Media-Type
				* Boundary
				* Content-Length
				* Content-Encoding
		3. `Request Headers`
			* The client sends [Request Headers](https://tools.ietf.org/html/rfc2616) in an HTTP transaction. These headers are `used in an HTTP request and do not relate to the content` of the message. The following headers are commonly seen in HTTP requests.
				* Host
				* User-Agent
				* Referer
				* Accept
				* Cookie
				* Authorization
		4. `Response Headers`
			* [Response Headers](https://tools.ietf.org/html/rfc7231#section-6) can be `used in an HTTP response and do not relate to the content`. Certain response headers such as `Age`, `Location`, and `Server` are used to provide more context about the response. The following headers are commonly seen in HTTP responses.
				* Server
				* Set-Cookie
				* WWW-Authenticate
		5. `Security Headers`
			* Finally, we have [Security Headers](https://owasp.org/www-project-secure-headers/). With the increase in the variety of browsers and web-based attacks, defining certain headers that enhanced security was necessary. HTTP Security headers are `a class of response headers used to specify certain rules and policies` to be followed by the browser while accessing the website.
				* Content-Security-Policy
				* Strict-Transport-Security
				* Referrer-Policy
	* **cURL**
		* In the previous section, we saw how using the `-v` flag with cURL shows us the full details of the HTTP request and response. If we were only interested in seeing the response headers, then we can use the `-I` flag to send a `HEAD` request and only display the response headers. Furthermore, we can use the `-i` flag to display both the headers and the response body (e.g. HTML code). The difference between the two is that `-I` sends a `HEAD` request (as will see in the next section), while `-i` sends any request we specify and prints the headers as well.
			* `curl -I https://inlanefreight.com`
		* In addition to viewing headers, cURL also allows us to set request headers with the `-H` flag, as we will see in a later section. Some headers, like the `User-Agent` or `Cookie` headers, have their own flags. For example, we can use the `-A` to set our `User-Agent`, as follows:
			* `curl https://inlanefreight.com -A 'Mozilla/5.0'`
	* **Browser DevTools**
		* In the first `Headers` tab, we see both the HTTP request and HTTP response headers. The devtools automatically arrange the headers into sections, but we can click on the `Raw` button to view their details in their raw format. Furthermore, we can check the `Cookies` tab to see any cookies used by the request, as discussed in an upcoming section.
* ## HTTP Methods and Codes
	* HTTP supports multiple methods for accessing a resource. In the HTTP protocol, several request methods allow the browser to send information, forms, or files to the server. These methods are used, among other things, to tell the server how to process the request we send and how to reply.
	* **Request Methods**
		* `GET` - Requests a specific resource. Additional data can be passed to the server via query strings in the URL (e.g. ?param=value).
		* `POST` - Sends data to the server. It can handle multiple types of input, such as text, PDFs, and other forms of binary data. This data is appended in the request body present after the headers. The POST method is commonly used when sending information (e.g. forms/logins) or uploading data to a website, such as images or documents.
		* `HEAD` - Requests the headers that would be returned if a GET request was made to the server. It doesn't return the request body and is usually made to check the response length before downloading resources.
		* `PUT` - Creates new resources on the server. Allowing this method without proper controls can lead to uploading malicious resources.
		* `DELETE` - Deletes an existing resource on the webserver. If not properly secured, can lead to Denial of Service (DoS) by deleting critical files on the web server.
		* `OPTIONS` - Returns information about the server, such as the methods accepted by it.
		* `PATCH` - Applies partial modifications to the resource at the specified location.
		* **Note:** Most modern web applications mainly rely on the `GET` and `POST` methods. However, any web application that utilizes REST APIs also rely on `PUT` and `DELETE`, which are used to update and delete data on the API endpoint, respectively. Refer to the [Introduction to Web Applications](https://academy.hackthebox.com/module/details/75) module for more details.
	* **Response Codes**
		* `1xx` - Provides information and does not affect the processing of the request.
		* `2xx` - Returned when a request succeeds.
		* `3xx` - Returned when the server redirects the client.
		* `4xx` - Signifies improper requests from the client. For example, requesting a resource that doesn't exist or requesting a bad format.
		* `5xx` - Returned when there is some problem with the HTTP server itself.
		* MOST COMMON:
			* `200 OK` - Returned on a successful request, and the response body usually contains the requested resource.
			* `302 Found` - Redirects the client to another URL. For example, redirecting the user to their dashboard after a successful login.
			* `400 Bad Request` - Returned on encountering malformed requests such as requests with missing line terminators.
			* `403 Forbidden` - Signifies that the client doesn't have appropriate access to the resource. It can also be returned when the server detects malicious input from the user.
			* `404 Not Found` - Returned when the client requests a resource that doesn't exist on the server.
			* `500 Internal Server Error` - Returned when the server cannot process the request.
		* For a a full list of standard HTTP response codes, you can visit this [link](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status). Apart from the standard HTTP codes, various servers and providers such as [Cloudflare](https://support.cloudflare.com/hc/en-us/articles/115003014432-HTTP-Status-Codes) or [AWS](https://docs.aws.amazon.com/AmazonSimpleDB/latest/DeveloperGuide/APIError.html) implement their own codes.
* ## GET
	* Whenever we visit any URL, our browsers default to a GET request to obtain the remote resources hosted at that URL. Once the browser receives the initial page it is requesting; it may send other requests using various HTTP methods. This can be observed through the Network tab in the browser devtools, as seen in the previous section.
* ## POST
	* Unlike HTTP `GET`, which places user parameters within the URL, HTTP `POST` places user parameters within the HTTP Request body. This has three main benefits:
		* `Lack of Logging`: As POST requests may transfer large files (e.g. file upload), it would not be efficient for the server to log all uploaded files as part of the requested URL, as would be the case with a file uploaded through a GET request.
		- `Less Encoding Requirements`: URLs are designed to be shared, which means they need to conform to characters that can be converted to letters. The POST request places data in the body which can accept binary data. The only characters that need to be encoded are those that are used to separate parameters.
		- `More data can be sent`: The maximum URL Length varies between browsers (Chrome/Firefox/IE), web servers (IIS, Apache, nginx), Content Delivery Networks (Fastly, Cloudfront, Cloudflare), and even URL Shorteners (bit.ly, amzn.to). Generally speaking, a URL's lengths should be kept to below 2,000 characters, and so they cannot handle a lot of data.
* ## CRUD API
	* There are several types of APIs. Many APIs are used to interact with a database, such that we would be able to specify the requested table and the requested row within our API query, and then use an HTTP method to perform the operation needed. 
	* As we can see, we can easily specify the table and the row we want to perform an operation on through such APIs. Then we may utilize different HTTP methods to perform different operations on that row. In general, APIs perform 4 main operations on the requested database entity:
		* `Create (POST)` - Adds the specified data to the database table
		* `Read (GET)` - Reads the specified entity from the database table
		* `Update (PUT)` - Updates the data of the specified database table
		* `Delete (DELETE)` - Removes the specified row from the database table
	* These four operations are mainly linked to the commonly known CRUD APIs, but the same principle is also used in REST APIs and several other types of APIs. Of course, not all APIs work in the same way, and the user access control will limit what actions we can perform and what results we can see.