# Guide to Automated Vulnerability Assessment

Hello! This is my first major project in Python, so I'm still learning. Please don't hesitate to contact me if you have any issues.

## Auto VA

I know that the vulnerability assessment process can't be fully automated because you need to check if the issues found by the tools are relevant to your use case. However, I tried to create something that could make your life easier.

So, let's get to the project. The main function of this project is to:

Given a list of hostnames and IPs, such as `Try 127.0.0.1,` it will iterate through the list, run Nmap on each IP, and create an OpenVAS task with the open ports found.

This will happen only with this command: `python main.py scanner {openvas username} {openvas password}`.

After all the jobs are completed, it's your turn to launch the task on OpenVAS. Once that's done, you can utilize the following command to download all reports:

`python main.py report {openvas username} {openvas password}`.

Please note that this program requires a filter ID (which you currently need to enter manually).

## To Do


1. Make all the project functions available on a Docker Compose system.
2. Allow the program to generate reports, not just download them.
3. Create a CI/CD pipeline so that the project can be deployed anywhere.