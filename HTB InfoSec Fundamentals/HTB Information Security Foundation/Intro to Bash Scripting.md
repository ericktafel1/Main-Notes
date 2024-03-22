* ## Bourne Again Shell
	*  Bash is the scripting language we use to communicate with Unix-based OS and give commands to the system. 
	* The main difference between scripting and programming languages is that we don't need to compile the code to execute the scripting language, as opposed to programming languages.
	* Like a programming language, a scripting language has almost the same structure, which can be divided into:
		* Input & Output
		* Arguments, Variables & Arrays
		* Conditional execution
		* Arithmetic
		* Loops
		* Comparison operators
		* Functions
	* In general, a script does not create a process, but it is executed by the interpreter that executes the script, in this case, the `Bash`. To execute a script, we have to specify the interpreter and tell it which script it should process. Such a call looks like this:
		* `bash script.sh <optional arguments>`
		* `sh script.sh <optional arguments>`
		* `./script.sh <optional arguments>`
	* Let us look at such a script and see how they can be created to get specific results. If we execute this script and specify a domain, we see what information this script provides.
		* `./CIDR.sh inlanefreight.com`
		* The script in detail:
			* ```#!/bin/bash
			
			# Check for given arguments
			if [ $# -eq 0 ]
			then
				echo -e "You need to specify the target domain.\n"
				echo -e "Usage:"
				echo -e "\t$0 <domain>"
				exit 1
			else
				domain=$1
			fi
			
			# Identify Network range for the specified IP address(es)
			function network_range {
				for ip in $ipaddr
				do
					netrange=$(whois $ip | grep "NetRange\|CIDR" | tee -a CIDR.txt)
					cidr=$(whois $ip | grep "CIDR" | awk '{print $2}')
					cidr_ips=$(prips $cidr)
					echo -e "\nNetRange for $ip:"
					echo -e "$netrange"
				done
			}
			
			# Ping discovered IP address(es)
			function ping_host {
				hosts_up=0
				hosts_total=0
				
				echo -e "\nPinging host(s):"
				for host in $cidr_ips
				do
					stat=1
					while [ $stat -eq 1 ]
					do
						ping -c 2 $host > /dev/null 2>&1
						if [ $? -eq 0 ]
						then
							echo "$host is up."
							((stat--))
							((hosts_up++))
							((hosts_total++))
						else
							echo "$host is down."
							((stat--))
							((hosts_total++))
						fi
					done
				done
				
				echo -e "\n$hosts_up out of $hosts_total hosts are up."
			}
			
			# Identify IP address of the specified domain
			hosts=$(host $domain | grep "has address" | cut -d" " -f4 | tee discovered_hosts.txt)
			
			echo -e "Discovered IP address:\n$hosts\n"
			ipaddr=$(host $domain | grep "has address" | cut -d" " -f4 | tr "\n" " ")
			
			# Available options
			echo -e "Additional options available:"
			echo -e "\t1) Identify the corresponding network range of target domain."
			echo -e "\t2) Ping discovered hosts."
			echo -e "\t3) All checks."
			echo -e "\t*) Exit.\n"
			
			read -p "Select your option: " opt
			
			case $opt in
				"1") network_range ;;
				"2") ping_host ;;
				"3") network_range && ping_host ;;
				"*") exit 0 ;;
			esac```
		* As we can see, we have commented here several parts of the script into which we can split it.
			1. Check for given arguments
			2. Identify network range for the specified IP address(es)
			3. Ping discovered IP address(es)
			4. Identify IP address(es) of the specified domain
			5. Available options
* ## Conditional Execution
	* Conditional execution allows us to control the flow of our script by reaching different conditions. 
	* When defining various conditions, we specify which functions or sections of code should be executed for a specific value. If we reach a specific condition, only the code for that condition is executed, and the others are skipped.
		* From first part of our ./CIDR.sh:
		* ```#!/bin/bash
		
		# Check for given argument
		if [ $# -eq 0 ]
		then
			echo -e "You need to specify the target domain.\n"
			echo -e "Usage:"
			echo -e "\t$0 <domain>"
			exit 1
		else
			domain=$1
		fi
		
		<SNIP>```
		* In summary, this code section works with the following components:
			- `#!/bin/bash` - Shebang.
			- `if-else-fi` - Conditional execution.
			- `echo` - Prints specific output.
			- `$#` / `$0` / `$1` - Special variables.
			- `domain` - Variables.
		- The conditions of the conditional executions can be defined using variables (`$#`, `$0`, `$1`, `domain`), values (`0`), and strings, as we will see in the next examples. These values are compared with the `comparison operators` (`-eq`).
		- **Shebang**
			- The shebang line is always at the top of each script and always starts with "`#!`". This line contains the path to the specified interpreter (`/bin/bash`) with which the script is executed. We can also use Shebang to define other interpreters like Python, Perl, and others.
				- `#!/usr/bin/env python` (Python)
				- `#!/usr/bin/env perl` (Perl)
		- **If-Else-Fi**
			- One of the most fundamental programming tasks is to check different conditions to deal with these. Checking of conditions usually has two different forms in programming and scripting languages, the `if-else condition` and `case statements`. In pseudo-code, the if condition means the following:
				- ```if [ the number of given arguments equals 0 ]
				then
					Print: "You need to specify the target domain."
					Print: "<empty line>"
					Print: "Usage:"
					Print: "   <name of the script> <domain>"
					Exit the script with an error
				else
					The "domain" variable serves as the alias for the given argument 
				finish the if-condition```
				* By default, an `If-Else` condition can contain only a single "`If`", as shown in the next example.
		* **If-Only.sh**
			* ```#!/bin/bash
			
			value=$1
			
			if [ $value -gt "10" ]
			then
			        echo "Given argument is greater than 10."
			fi```
		* **If-Only.sh - Execution**
			* `bash if-only.sh 5`
			* `bash if-only.sh 12`
			`Given argument is greater than 10.`
			* When adding `Elif` or `Else`, we add alternatives to treat specific values or statuses. If a particular value does not apply to the first case, it will be caught by others.
		* **If-Elif-Else.sh**
			* ```#!/bin/bash
			
			value=$1
			
			if [ $value -gt "10" ]
			then
				echo "Given argument is greater than 10."
			elif [ $value -lt "10" ]
			then
				echo "Given argument is less than 10."
			else
				echo "Given argument is not a number."
			fi```
		* **If-Elif-Else.sh - Execution**
			* ```bash if-elif-else.sh 5
			Given argument is less than 10.```
			* ```bash if-elif-else.sh 12
			Given argument is greater than 10.```
			* ```bash if-elif-else.sh HTB
			if-elif-else.sh: line 5: [: HTB: integer expression expected
			if-elif-else.sh: line 8: [: HTB: integer expression expected
			Given argument is not a number.```
			* We could extend our script and specify several conditions. This could look something like this:
		* **Several Conditions - Script.sh**
			* ```#!/bin/bash
			
			# Check for given argument
			if [ $# -eq 0 ]
			then
				echo -e "You need to specify the target domain.\n"
				echo -e "Usage:"
				echo -e "\t$0 <domain>"
				exit 1
			elif [ $# -eq 1 ]
			then
				domain=$1
			else
				echo -e "Too many arguments given."
				exit 1
			fi
			
			<SNIP>```
			* Here we define another condition (`elif [<condition>];then`) that prints a line telling us (`echo -e "..."`) that we have given more than one argument and exits the program with an error (`exit 1`).
		* **Exercise Script**
			* ```#!/bin/bash
			# Count number of characters in a variable:
			#     echo $variable | wc -c
			
			# Variable to encode
			var="nef892na9s1p9asn2aJs71nIsm"
			
			for counter in {1..40}
			do
			        var=$(echo $var | base64)
			done```
			* **Add If-Else to return 35th value**
			* ```#!/bin/bash
			
			# Count number of characters in a variable:
			#     echo $variable | wc -c
			
			# Variable to encode
			var="nef892na9s1p9asn2aJs71nIsm"
			
			for counter in {1..40}
			do
			    var=$(echo $var | base64)
			    
			    # Check if it's the 35th iteration
			    if [ $counter -eq 35 ]; then
			        num_chars=$(echo -n "$var" | wc -c)
			        echo $num_chars
			    fi
			done```
* ## Arguments, Variables, and Arrays
	* **Arguments**
		* The advantage of bash scripts is that we can always pass up to 9 arguments (`$0`-`$9`) to the script without assigning them to variables or setting the corresponding requirements for these.
			* `9 arguments` because the first argument `$0` is reserved for the script. As we can see here, we need the dollar sign (`$`) before the name of the variable to use it at the specified position. The assignment would look like this in comparison:
				* ```./script.sh ARG1 ARG2 ARG3 ... ARG9
			       ASSIGNMENTS:       $0      $1   $2   $3 ...   $9```
		* This means that we have automatically assigned the corresponding arguments to the predefined variables in this place. These variables are called special variables. These special variables serve as placeholders. If we now look at the code section again, we will see where and which arguments have been used.
			* ```#!/bin/bash
			# Check for given argument
			if [ $# -eq 0 ]
			then
				echo -e "You need to specify the target domain.\n"
				echo -e "Usage:"
				echo -e "\t$0 <domain>"
				exit 1
			else
				domain=$1
			fi
			
			<SNIP>```
		* There are several ways how we can execute our script. However, we must first set the script's execution privileges before executing it with the interpreter defined in it.
			* `chmod +x cidr.sh`
		* **Special Variables**
			* Special variables use the [Internal Field Separator](https://bash.cyberciti.biz/guide/$IFS) (`IFS`) to identify when an argument ends and the next begins. Bash provides various special variables that assist while scripting. Some of these variables are:
				* `$#` - This variable holds the number of arguments passed to the script.
				* `$@` - This variable can be used to retrieve the list of command-line arguments.
				* `$n` - Each command-line argument can be selectively retrieved using its position. For example, the first argument is found at `$1`.
				* `$$` - The process ID of the currently executing process.
				* `$?` - The exit status of the script. This variable is useful to determine a command's success. The value 0 represents successful execution, while 1 is a result of a failure.
			* Of the ones shown above, we have 3 such special variables in our `if-else` condition.
				* `$#` - In this case, we need just one variable that needs to be assigned to the `domain` variable. This variable is used to specify the target we want to work with. If we provide just an FQDN as the argument, the `$#` variable will have a value of `1`.
				* `$0` - This special variable is assigned the name of the executed script, which is then shown in the "`Usage:`" example.
				* `$1` - Separated by a space, the first argument is assigned to that special variable.
	* **Variables**
		* We also see at the end of the if-else loop that we assign the value of the first argument to the variable called "`domain`". The assignment of variables takes place without the dollar sign (`$`). T**he dollar sign is only intended to allow this variable's corresponding value to be used in other code sections.** When assigning variables, there must be no spaces between the names and values.
		* In contrast to other programming languages, there is no direct differentiation and recognition between the types of variables in Bash like "`strings`," "`integers`," and "`boolean`." All contents of the variables are treated as string characters. Bash enables arithmetic functions depending on whether only numbers are assigned or not. It is important to note when declaring variables that they do `not` contain a `space`. Otherwise, the actual variable name will be interpreted as an internal function or a command.
			* `variable="this works"` (GOOD)
			* `variable = "this does not work"` (BAD)
	* **Arrays**
		* There is also the possibility of assigning several values to a single variable in Bash. This can be beneficial if we want to scan multiple domains or IP addresses. These variables are called `arrays` that we can use to store and process an ordered sequence of specific type values. `Arrays` identify each stored entry with an `index` starting with `0`. When we want to assign a value to an array component, we do so in the same way as with standard shell variables. All we do is specify the field index enclosed in square brackets. The declaration for `arrays` looks like this in Bash:
			* ```#!/bin/bash
			
			domains=(www.inlanefreight.com ftp.inlanefreight.com vpn.inlanefreight.com www2.inlanefreight.com)
			
			echo ${domains[0]}```
		* We can also retrieve them individually using the index using the variable with the corresponding index in curly brackets. Curly brackets are used for variable expansion.
		* It is important to note that single quotes (`'` ... `'`) and double quotes (`"` ... `"`) prevent the separation by a space of the individual values in the array. This means that all spaces between the single and double quotes are ignored and handled as a single value assigned to the array.
			* ```#!/bin/bash
			
			domains=("www.inlanefreight.com ftp.inlanefreight.com vpn.inlanefreight.com" www2.inlanefreight.com)
			echo ${domains[0]}```
* ## Comparison Operators
	* To compare specific values with each other, we need elements that are called [comparison operators](https://www.tldp.org/LDP/abs/html/comparison-ops.html).
	* The `comparison operators` are used to determine how the defined values will be compared. For these operators, we differentiate between:
		* `string` operators
		- `integer` operators
		- `file` operators
		- `boolean` operators
	- **String Operators**
		- `==` - is equal to
		- `!=` - is not equal to
		- `<` - is less than in ASCII alphabetical order
		- `>` - is greater than in ASCII alphabetical order
		- `-z` - if the string is empty (null)
		- `-n` - if the string is not null
	- It is important to note here that we put the variable for the given argument (`$1`) in double-quotes (`"$1"`). This tells Bash that the content of the variable should be handled as a string. Otherwise, we would get an error.
		- ```#!/bin/bash
		
		# Check the given argument
		if [ "$1" != "HackTheBox" ]
		then
			echo -e "You need to give 'HackTheBox' as argument."
			exit 1
		
		elif [ $# -gt 1 ]
		then
			echo -e "Too many arguments given."
			exit 1
		
		else
			domain=$1
			echo -e "Success!"
		fi```
		* String comparison operators "`<` / `>`" works only within the double square brackets `[[ <condition> ]]`. We can find the ASCII table on the Internet or by using the following command in the terminal. We take a look at an example later.
			* `man ascii`
			* `ASCII` stands for `American Standard Code for Information Interchange` and represents a 7-bit character encoding. Since each bit can take two values, there are `128` different bit patterns, which can also be interpreted as the decimal integers `0` - `127` or in hexadecimal values `00` - `7F`. The first 32 ASCII character codes are reserved as so-called [control characters](https://en.wikipedia.org/wiki/Control_character).
			* ![[Pasted image 20231121144238.png]]
	* **Integer Operators**
		* `-eq` - is equal to
		* `-ne` - is not equal to
		* `-lt` - is less than
		* `-le` - is less than or equal to
		* `-gt` - is greater than
		* `-ge` - is greater than or equal to
			* ```#!/bin/bash
			
			# Check the given argument
			if [ $# -lt 1 ]
			then
				echo -e "Number of given arguments is less than 1"
				exit 1
			
			elif [ $# -gt 1 ]
			then
				echo -e "Number of given arguments is greater than 1"
				exit 1
			
			else
				domain=$1
				echo -e "Number of given arguments equals 1"
			fi```
	* **File Operators**
		* The file operators are useful if we want to find out specific permissions or if they exist.
			* `-e` - if the file exist
			* `-f` - tests if it is a file
			* `-d` - tests if it is a directory
			* `-L` - tests if it is if a symbolic link
			* `-N` - checks if the file was modified after it was last read
			* `-O` - if the current user owns the file
			* `-G` - if the file’s group id matches the current user’s
			* `-s` - tests if the file has a size greater than 0
			* `-r` - tests if the file has read permission
			* `-w` - tests if the file has write permission
			* `-x` - tests if the file has execute permission
				* ```#!/bin/bash
				
				# Check if the specified file exists
				if [ -e "$1" ]
				then
					echo -e "The file exists."
					exit 0
				
				else
					echo -e "The file does not exist."
					exit 2
				fi```
	* **Boolean and Logical Operators**
		* We get a boolean value "`false`" or "`true`" as a result with logical operators. Bash gives us the possibility to compare strings by using double square brackets `[[ <condition> ]]`.
			* To get these boolean values, we can use the string operators. Whether the comparison matches or not, we get the boolean value "`false`" or "`true`".
			* ```#!/bin/bash
			
			# Check the boolean value
			if [[ -z $1 ]]
			then
				echo -e "Boolean value: True (is null)"
				exit 1
			
			elif [[ $# > 1 ]]
			then
				echo -e "Boolean value: True (is greater than)"
				exit 1
			
			else
				domain=$1
				echo -e "Boolean value: False (is equal to)"
			fi```
		* **Logical Operators**
			* With logical operators, we can define several conditions within one. This means that all the conditions we define must match before the corresponding code can be executed.
				* `!` - logical negotation NOT
				* `&&` - logical AND
				* `||` - logical OR
					* ```#!/bin/bash
					
					# Check if the specified file exists and if we have read permissions
					if [[ -e "$1" && -r "$1" ]]
					then
						echo -e "We can read the file that has been specified."
						exit 0
					
					elif [[ ! -e "$1" ]]
					then
						echo -e "The specified file does not exist."
						exit 2
					
					elif [[ -e "$1" && ! -r "$1" ]]
					then
						echo -e "We don't have read permission for this file."
						exit 1
					
					else
						echo -e "Error occured."
						exit 5
					fi```
		* **Exercise Script**
			* ```#!/bin/bash
			
			var="8dm7KsjU28B7v621Jls"
			value="ERmFRMVZ0U2paTlJYTkxDZz09Cg"
			
			for i in {1..40}
			do
			        var=$(echo $var | base64)
					
					#<---- If condition here:
			done```
			* Answer...
				* ```#!/bin/bash
				var="8dm7KsjU28B7v621Jls"
				value="ERmFRMVZ0U2paTlJYTkxDZz09Cg"
				for i in {1..40};
				do
				        var=$(echo "$var" | base64)
				        char=$(echo "$var" | wc -c)
				        if [[ "$var" == *"$value"* ]]; then
				                if [ "$char" -gt "113469" ]; then
				                        last=${var: -20}
				                        echo "$last"
				                fi
				        fi
				done```
				* checked count since it wasnt correct. Removed the first character.
				`echo "U2paTlJYTkxDZz09Cg==" | wc -c`
* ## Arithmetic
	* Seven different `arithmetic operators` we can work with. These are used to perform different mathematical operations or to modify certain integers.
		* `+` Addition
		* `-` Subtraction
		* `*` Multiplication
		* `/` Division
		* `%` Modulus
		* `variable++` Increase the value of the variable by 1
		* `variable--` Decrease the value of the variable by 1
	* Arithmetic.sh
		* ```#!/bin/bash
		
		increase=1
		decrease=1
		
		echo "Addition: 10 + 10 = $((10 + 10))"
		echo "Substraction: 10 - 10 = $((10 - 10))"
		echo "Multiplication: 10 * 10 = $((10 * 10))"
		echo "Division: 10 / 10 = $((10 / 10))"
		echo "Modulus: 10 % 4 = $((10 % 4))"
		
		((increase++))
		echo "Increase Variable: $increase"
		
		((decrease--))
		echo "Decrease Variable: $decrease"```
	* The output of this script looks like this:
		* ```Addition: 10 + 10 = 20
		Substraction: 10 - 10 = 0
		Multiplication: 10 * 10 = 100
		Division: 10 / 10 = 1
		Modulus: 10 % 4 = 2
		Increase Variable: 2
		Decrease Variable: 0```
	* We can also calculate the length of the variable. Using this function `${#variable}`, every character gets counted, and we get the total number of characters in the variable.
	* VarLength.sh
		* ```#!/bin/bash
		htb="HackTheBox"
		echo ${#htb}```
		* `10`
	* If we look at our `CIDR.sh` script, we will see that we have used the `increase` and `decrease` operators several times. This ensures that the while loop, which we will discuss later, runs and pings the hosts while the variable "`stat`" has a value of `1`. If the ping command ends with code `0` (successful), we get a message that the `host is up` and the "`stat`" variable, as well as the variables "`hosts_up`" and "`hosts_total`" get changed.
		* ```<SNIP>
			echo -e "\nPinging host(s):"
			for host in $cidr_ips
			do
				stat=1
				while [ $stat -eq 1 ]
				do
					ping -c 2 $host > /dev/null 2>&1
					if [ $? -eq 0 ]
					then
						echo "$host is up."
						((stat--))
						((hosts_up++))
						((hosts_total++))
					else
						echo "$host is down."
						((stat--))
						((hosts_total++))
					fi
				done
			done
		<SNIP>```
* ## Input and Output
	* **Input Control**
		* Be familiar with how to get a running script to wait for our instructions. If we look at our `CIDR.sh` script again, we see that we have added such a call to decide further steps.
			* ```# Available options
			<SNIP>
			echo -e "Additional options available:"
			echo -e "\t1) Identify the corresponding network range of target domain."
			echo -e "\t2) Ping discovered hosts."
			echo -e "\t3) All checks."
			echo -e "\t*) Exit.\n"
			
			read -p "Select your option: " opt
			
			case $opt in
				"1") network_range ;;
				"2") ping_host ;;
				"3") network_range && ping_host ;;
				"*") exit 0 ;;
			esac```
		* The first `echo` lines serve as a display menu for the options available to us.
		* With the `read` command, the line with "`Select your option:`" is displayed, and the additional option `-p` ensures that our input remains on the same line.
		* Our input is stored in the variable `opt`, which we then use to execute the corresponding functions with the `case` statement, which we will look at later. Depending on the number we enter, the `case` statement determines which functions are executed.
	* **Output Control**
		* Check the `Linux Fundamentals` module.
		* The problem with the redirections is that we do not get any output from the respective command. It will be redirected to the appropriate file. 
		* To avoid sitting inactively and waiting for our script's results, we can use the [tee](https://man7.org/linux/man-pages/man1/tee.1.html) utility. It ensures that we see the results we get immediately and that they are stored in the corresponding files. In our `CIDR.sh` script, we have used this utility twice in different ways.
			* ```<SNIP>
			
			# Identify Network range for the specified IP address(es)
			function network_range {
				for ip in $ipaddr
				do
					netrange=$(whois $ip | grep "NetRange\|CIDR" | tee -a CIDR.txt)
					cidr=$(whois $ip | grep "CIDR" | awk '{print $2}')
					cidr_ips=$(prips $cidr)
					echo -e "\nNetRange for $ip:"
					echo -e "$netrange"
				done
			}
			
			<SNIP>
			
			# Identify IP address of the specified domain
			hosts=$(host $domain | grep "has address" | cut -d" " -f4 | tee discovered_hosts.txt)
			
			<SNIP>```
		* When using `tee`, we transfer the received output and use the pipe (`|`) to forward it to `tee`.
		* The "`-a` / `--append`" parameter ensures that the specified file is not overwritten but supplemented with the new results.
		* At the same time, it shows us the results and how they will be found in the file.
* ## Flow Control - Loops
	* We have already learned about the `if-else` conditions, which are also part of flow control.
	* Each control structure is either a `branch` or a `loop`. Logical expressions of boolean values usually control the execution of a control structure. These control structures include:
		* **Branches**:
		    - `If-Else` Conditions
		    - `Case` Statements
		- **Loops**:
		    - `For` Loops
		    - `While` Loops
		    - `Until` Loops
	* **For Loops**
		* The `For` loop is executed on each pass for precisely one parameter, which the shell takes from a list, calculates from an increment, or takes from another data source.
		* Runs as long as it finds corresponding data. T
		* For example, the for loops are often used when we need to work with many different values from an array. This can be used to scan different hosts or ports. We can also use it to execute specific commands for known ports and their services to speed up our enumeration process. The syntax for this can be as follows:
			* ```for variable in 1 2 3 4
			do
				echo $variable
			done```
			* ```for variable in file1 file2 file3
			do
				echo $variable
			done```
			* ```for ip in "10.10.10.170 10.10.10.174 10.10.10.175"
			do
				ping -c 1 $ip
			done```
		* Of course, we can also write these commands in a single line. Such a command would look like this:
			* `for ip in 10.10.10.170 10.10.10.174;do ping -c 1 $ip;done`
		* Let us have another look at our `CIDR.sh` script. We have added several for loops to the script, but let us stick with this little code section.
			* ```<SNIP>
			
			# Identify Network range for the specified IP address(es)
			function network_range {
				for ip in $ipaddr
				do
					netrange=$(whois $ip | grep "NetRange\|CIDR" | tee -a CIDR.txt)
					cidr=$(whois $ip | grep "CIDR" | awk '{print $2}')
					cidr_ips=$(prips $cidr)
					echo -e "\nNetRange for $ip:"
					echo -e "$netrange"
				done
			}
			
			<SNIP>```
		* As in the previous example, for each IP address from the array "`ipaddr`" we make a "`whois`" request, whose output is filtered for "`NetRange`" and "`CIDR`." This helps us to determine which address range our target is located in. We can use this information to search for additional hosts during a penetration test, `if approved by the client`. The results that we receive are displayed accordingly and stored in the file "`CIDR.txt`."
	* **While Loops**
		* The `while` loop is conceptually simple and follows the following principle:
			- A statement is executed as long as a condition is fulfilled (`true`).
		* We can also combine loops and merge their execution with different values. It is important to note that the excessive combination of several loops in each other can make the code very unclear and lead to errors that can be hard to find and follow. Such a combination can look like in our `CIDR.sh` script.
			* ```<SNIP>
					stat=1
					while [ $stat -eq 1 ]
					do
						ping -c 2 $host > /dev/null 2>&1
						if [ $? -eq 0 ]
						then
							echo "$host is up."
							((stat--))
							((hosts_up++))
							((hosts_total++))
						else
							echo "$host is down."
							((stat--))
							((hosts_total++))
						fi
					done
			<SNIP>```
		* The `while` loops also work with conditions like `if-else`.
		* **A while loop needs some sort of a counter to orientate itself when it has to stop executing the commands it contains**. Otherwise, this leads to an endless loop.
			* Such a counter can be a variable that we have declared with a specific value or a boolean value.
			* `While` loops run while the boolean value is "`True`".
			* Besides the counter, we can also use the command "`break`," which interrupts the loop when reaching this command like in the following example:
				* ```#!/bin/bash
				
				counter=0
				
				while [ $counter -lt 10 ]
				do
				  # Increase $counter by 1
				  ((counter++))
				  echo "Counter: $counter"
				  if [ $counter == 2 ]
				  then
					  continue
				  elif [ $counter == 4 ]
				  then
					  break
				  fi
				done```
				* Output:
					* ```Counter: 1
					Counter: 2
					Counter: 3
					Counter: 4```
	* **Until Loops**
		* There is also the `until` loop, which is relatively rare. Nevertheless, the `until` loop works precisely like the `while` loop, but with the difference:
			- The code inside a `until` loop is executed as long as the particular condition is `false`.
		* The other way is to let the loop run until the desired value is reached. The "`until`" loops are very well suited for this. This type of loop works similarly to the "`while`" loop but, as already mentioned, with the difference that it runs until the boolean value is "`False`."
			* ```#!/bin/bash
			
			counter=0
			
			until [ $counter -eq 10 ]
			do
			  # Increase $counter by 1
			  ((counter++))
			  echo "Counter: $counter"
			done```
			* Output:
				* ```Counter: 1
				Counter: 2
				Counter: 3
				Counter: 4
				Counter: 5
				Counter: 6
				Counter: 7
				Counter: 8
				Counter: 9
				Counter: 10```
	* **Exercise Script**
		* ```#!/bin/bash
		# Decrypt function
		function decrypt {
		        MzSaas7k=$(echo $hash | sed 's/988sn1/83unasa/g')
		        Mzns7293sk=$(echo $MzSaas7k | sed 's/4d298d/9999/g')
		        MzSaas7k=$(echo $Mzns7293sk | sed 's/3i8dqos82/873h4d/g')
		        Mzns7293sk=$(echo $MzSaas7k | sed 's/4n9Ls/20X/g')
		        MzSaas7k=$(echo $Mzns7293sk | sed 's/912oijs01/i7gg/g')
		        Mzns7293sk=$(echo $MzSaas7k | sed 's/k32jx0aa/n391s/g')
		        MzSaas7k=$(echo $Mzns7293sk | sed 's/nI72n/YzF1/g')
		        Mzns7293sk=$(echo $MzSaas7k | sed 's/82ns71n/2d49/g')
		        MzSaas7k=$(echo $Mzns7293sk | sed 's/JGcms1a/zIm12/g')
		        Mzns7293sk=$(echo $MzSaas7k | sed 's/MS9/4SIs/g')
		        MzSaas7k=$(echo $Mzns7293sk | sed 's/Ymxj00Ims/Uso18/g')
		        Mzns7293sk=$(echo $MzSaas7k | sed 's/sSi8Lm/Mit/g')
		        MzSaas7k=$(echo $Mzns7293sk | sed 's/9su2n/43n92ka/g')
		        Mzns7293sk=$(echo $MzSaas7k | sed 's/ggf3iunds/dn3i8/g')
		        MzSaas7k=$(echo $Mzns7293sk | sed 's/uBz/TT0K/g')
		        
		        flag=$(echo $MzSaas7k | base64 -d | openssl enc -aes-128-cbc -a -d -salt -pass pass:$salt)
		}
		
		# Variables
		var="9M"
		salt=""
		hash="VTJGc2RHVmtYMTl2ZnYyNTdUeERVRnBtQWVGNmFWWVUySG1wTXNmRi9rQT0K"
		
		# Base64 Encoding Example:
		#        $ echo "Some Text" | base64
		
		# <- For-Loop here
		for i in {1..28}
		do
		  var=$(echo "$var" | base64 )
		done
		salt=$(( ${#var} + 1 ))
		
		# Check if $salt is empty
		if [[ ! -z "$salt" ]]
		then
		        decrypt
		        echo $flag
		else
		        exit 1
		fi```
* ## Flow Control - Branches
	* As we have already seen, the branches in flow control include `if-else` and the `case` statements. We have already discussed the `if-else` statements in detail and know how this works.
	* **Case Statements**
		* `Case` statements are also known as `switch-case` statements in other languages, such as C/C++ and C#.
		* The main difference between `if-else` and `switch-case` is that `if-else` constructs allow us to check any boolean expression, while `switch-case` always compares only the variable with the exact value. Therefore, the same conditions as for `if-else`, such as "greater-than," are not allowed for `switch-case`. The syntax for the switch-case statements looks like this:
			* ```case <expression> in
				pattern_1 ) statements ;;
				pattern_2 ) statements ;;
				pattern_3 ) statements ;;
			esac```
		* The definition of switch-case starts with `case`, followed by the variable or value as an expression, which is then compared in the pattern. If the variable or value matches the expression, then the statements are executed after the parenthesis and ended with a double semicolon (`;;`).
		* In our `CIDR.sh` script, we have used such a `case` statement. Here we defined four different options that we assigned to our script, how it should proceed after our decision.
			* ```<SNIP>
			# Available options
			echo -e "Additional options available:"
			echo -e "\t1) Identify the corresponding network range of target domain."
			echo -e "\t2) Ping discovered hosts."
			echo -e "\t3) All checks."
			echo -e "\t*) Exit.\n"
			
			read -p "Select your option: " opt
			
			case $opt in
				"1") network_range ;;
				"2") ping_host ;;
				"3") network_range && ping_host ;;
				"*") exit 0 ;;
			esac
			<SNIP>```
	* ## Functions
		* The bigger our scripts get, the more chaotic they become.
		* In such cases, `functions` are the solution that improves both the size and the clarity of the script many times.
		* We combine several commands in a block between curly brackets ( `{` ... `}` ) and call them with a function name defined by us with `functions`. Once a function has been defined, it can be called and used again during the script.
		* `Functions` are an essential part of scripts and programs, as they are used to execute recurring commands for different values and phases of the script or program. Therefore, we do not have to repeat the whole section of code repeatedly but can create a single function that executes the specific commands. 
		* It is important to note that functions must always be defined logically `before` the first call since a script is also processed from top to bottom. Therefore the definition of a function is always `at the beginning` of the script. There are two methods to define the functions:
			* Method 1
				* ```function name {
					<commands>
				}```
			* Method 2
				* ```name() {
					<commands>
				}```
		* We can choose the method to define a function that is most comfortable for us. In our `CIDR.sh` script, we used the first method because it is easier to read with the keyword "`function`."
			* ```<SNIP>
			# Identify Network range for the specified IP address(es)
			function network_range {
				for ip in $ipaddr
				do
					netrange=$(whois $ip | grep "NetRange\|CIDR" | tee -a CIDR.txt)
					cidr=$(whois $ip | grep "CIDR" | awk '{print $2}')
					cidr_ips=$(prips $cidr)
					echo -e "\nNetRange for $ip:"
					echo -e "$netrange"
				done
			}
			<SNIP>```
		* The function is called only by calling the specified name of the function, as we have seen in the case statement.
			* ```<SNIP>
			case $opt in
				"1") network_range ;;
				"2") ping_host ;;
				"3") network_range && ping_host ;;
				"*") exit 0 ;;
			esac```
		* **Parameter Passing**
			* Like we have already seen in our `CIDR.sh` script, we used the format of an IP address for the function "`network_range`". The parameters are optional, and therefore we can call the function without parameters. In principle, the same applies to the passed parameters as to parameters passed to a shell script.
				* These are `$1` - `$9` (`${n}`), or `$variable` as we have already seen. Each function has its own set of parameters. So they do not collide with those of other functions or the parameters of the shell script.
			* An important difference between bash scripts and other programming languages is that all defined variables are always processed `globally` unless otherwise declared by "[local](https://www.tldp.org/LDP/abs/html/localvar.html)." This means that the first time we have defined a variable in a function, we will call it in our main script (outside the function). Passing the parameters to the functions is done the same way as we passed the arguments to our script and looks like this:
				* ```#!/bin/bash
				function print_pars {
					echo $1 $2 $3
				}
				
				one="First parameter"
				two="Second parameter"
				three="Third parameter"
				
				print_pars "$one" "$two" "$three"```
				* Output:
					* `First parameter Second parameter Third parameter`
		* **Return Values**
			* When we start a new process, each `child process` (for example, a `function` in the executed script) returns a `return code` to the `parent process` (`bash shell` through which we executed the script) at its termination, informing it of the status of the execution.
			* This information is used to determine whether the process ran successfully or whether specific errors occurred. Based on this information, the `parent process` can decide on further program flow.
				* `1` - General errors
				* `2` - Misuse of shell builtins
				* `126` - Command invoked cannot execute
				* `127` - Command not found
				* `128` - Invalid argument to exit
				* `128+n` - Fatal error signal "`n`"
				* `130` - Script terminated by Control-C
				* `255\*` - Exit status out of range
			* To get the value of a function back, we can use several methods like `return`, `echo`, or a `variable`. In the next example, we will see how to use "`$?`" to read the "`return code`," how to pass the arguments to the function and how to assign the result to a variable.
				* ```#!/bin/bash
				
				function given_args {
				        if [ $# -lt 1 ]
				        then
				                echo -e "Number of arguments: $#"
				                return 1
				        else
				                echo -e "Number of arguments: $#"
				                return 0
				        fi
				}
				
				# No arguments given
				given_args
				echo -e "Function status code: $?\n"
				
				# One argument given
				given_args "argument"
				echo -e "Function status code: $?\n"
				
				# Pass the results of the funtion into a variable
				content=$(given_args "argument")
				
				echo -e "Content of the variable: \n\t$content"```
			* Output:
				* ```Number of arguments: 0
				Function status code: 1
				
				Number of arguments: 1
				Function status code: 0
				
				Content of the variable:
				Number of arguments: 1```
	* ## Debugging
		* Bash gives us an excellent opportunity to find, track, and fix errors in our code. The term `debugging` can have many different meanings. Nevertheless, [Bash debugging](https://tldp.org/LDP/Bash-Beginners-Guide/html/sect_02_03.html) is the process of removing errors (bugs) from our code.
		* Debugging can be performed in many different ways.
			* For example, we can use our code for debugging to check for typos, or we can use it for code analysis to track them and determine why specific errors occur.
		* This process is also used to find vulnerabilities in programs.
			* For example, we can try to cause errors using different input types and track their handling in the CPU through the assembler, which may provide a way to manipulate the handling of these errors to insert our own code and force the system to execute it. This topic will be covered and discussed in detail in other modules. Bash allows us to debug our code by using the "`-x`" (`xtrace`) and "`-v`" options. Now let us see an example with our `CIDR.sh` script.
				* `bash -x CIDR.sh`
				* Output: 
					* `+ '[' 0 -eq 0 ']'`
					`+ echo -e 'You need to specify the target domain.\n'`
					`You need to specify the target domain.`
					
					`+ echo -e Usage:`
					`Usage:`
					`+ echo -e '\tCIDR.sh <domain>'`
					`	CIDR.sh <domain>`
					`+ exit 1`
				* `bash -x -v CIDR.sh`
				* Output:
					* ```#!/bin/bash
					
					# Check for given argument
					if [ $# -eq 0 ]
					then
						echo -e "You need to specify the target domain.\n"
						echo -e "Usage:"
						echo -e "\t$0 <domain>"
						exit 1
					else
						domain=$1
					fi```
					`+ '[' 0 -eq 0 ']'`
					`+ echo -e 'You need to specify the target domain.\n'`
					`You need to specify the target domain.`
					
					`+ echo -e Usage:`
					`Usage:`
					`+ echo -e '\tCIDR.sh <domain>'`
					`	CIDR.sh <domain>`
					`+ exit 1`
			* In comparison to normal debugging, we see the entire code section that has been processed so far and then the individual steps that have been taken.