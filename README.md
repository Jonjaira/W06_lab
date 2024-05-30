Command Injection
The assignment is to simulate a SQL Injection attack by writing a function that accepts two input parameters and returns a SQL string. We will then write a function to demonstrate the query generation function works as expected with a collection of test cases. Next, a collection of test cases will be generated that demonstrate that the function is vulnerable to a variety of command injection attacks: tautology, additional statement, comment attacks, and union queries. Code will be written to provide weak mitigation to each of these attacks. Finally, code will be written to provide strong mitigation.

Query Generation
Write a function to accept two strings (username and a password) and return a single string (SQL) representing the query used to determine if a user is authenticated on a given system. The query will be similar to one presented in the textbook. Provide the code for the function in the report and a couple sentences justifying that it works the way one would expect.


Generate a set of cases (one for each member of your team) that represent valid input where the username and the password consist of letters, numbers, and underscores. Create a function that feeds these test cases through the query function and displays the resulting query. Provide the code in the report, a sample of the output from the function, and a couple sentences justifying why the test cases provide adequate coverage of the valid input.


Vulnerabilities
Generate test cases (again, each team member should generate one test case) that demonstrate a tautology attack. Create a function that feeds these test cases through the query function and displays the output. Provide the code, output, and justification in the lab report.


Do the same thing for a union query attack, an additional statement attack, and a comment attack. As with tautology, each attack must be demonstrated with a separate set of test cases, a separate function feeding the test cases to the query function, and justification in the lab report.


Weak Mitigation
Create a function to provide a weak mitigation against all four attacks. This function accepts the input as a parameter (or two!) and returns the sanitized input. In the lab report, provide the code, the output of the various test cases, and justification that the code represents a weak mitigation to the four attack types.


Strong Mitigation
Create a function to provide a strong mitigation against all command injection attacks. Provide the code, output showing that the valid test cases still work, output showing that all four malicious inputs are mitigated, and a justification the approach works the way one would expect.


Lab Report
As with last week the main deliverable for this lab will be the lab report. This concise, professionally written document will include the code fragments, test cases, the relevant output, a brief description of what is presented, and justification that the code matches the theoretical framework described in the class.

This lab report is the most important deliverable. This report should honor all of the guidelines presented in the Scholarly Writing document.

Assignment
There will be one submission constituting all of the work of your team. This submission will include:

Lab Report: A lab report in PDF format.
Source Code: All the source code generated for this assignment in a single source code file. By downloading the file and running it, it should be possible to execute any of the test cases in the report. A simple menu structure should be provided to facilitate this.
Demo Video: A short video demonstrating your program. This should show the running of test cases. The video should be a link to stream it directly rather than a file to download.
