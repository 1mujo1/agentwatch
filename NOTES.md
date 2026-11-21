# AgentWatch: my notes (in my own words)

## Design decisions
- M3: auditd instead of Sysmon for Linux. Reason:
- M1: cuz doker can not translate uids and the kernal does , so the ability to the agent to access the workspace folder will impossible , so we must use ACLS rather than using chmod cuz it is wrong fix
## M0: Setup
- What I built:tested all tools used in project , create all need 5 files in woekspace folder
- Why:so every thing all be done before the actual implementation of the project , the files are utils.py contains python code to tested by the agent , test_utils.py this the main code that going to test , conftest.py cuz the test file in subfolder this needed for module import , .env file and it has a fake api_key for test also , read.me so the agent can read it  
- Security concept:remove the ccahe that cuased from the testing cuz it can not be logged by auditp in further implementation.

## M1: Sandbox container
created a internal network so i can cummunicate with the agent by using dockr network 
- security concepts:using the internal network to limit the agent into not accessing the outside world rather than limiting him into using specpic tools  
## M2: Egress proxy
Security concepts:
- Default deny / allow-listing: block everything, allow only what's needed. That's the opposite of a block-list, which tries to guess every bad site and always misses some.
- Breaking the lethal trifecta: the agent has secrets and untrusted input, but no way out except through a guard.
- The attempt is the alert: even a blocked request leaves evidence in proxy.log.
1-created allow-list file to limit the agent into specifec website.
2-created tinyproxy conf file for configeration 
3-created dockerfile that install tinyproxy and on it building the image agentwatch-proxy 
4- runnung the container proxy on specfic flags 
5- connecting agentnet network to proxy and in the end i test it 
## M3: auditd
Security concepts:
- Ground truth: the kernel is the one witness that can't be talked out of it
- Syscall auditing: every action a program takes ends up as a system call (execve, connect, unlink, openat)
- Attribution: filter on uid 4242 = only the agent, without your laptop's noise
1- installind auditd 
2- i have put the rules in agentwatch.rules 
3- i have tested them by performing command on the agent container and i have seen the evidence using aureport and ausearch
4- converting the evidence to human readable launguge such as jsonl .
## M4: Agent + hooks + scenarios

1- created log_hook python script and and claude-settings json for hook config
2- and then tested everything works
## M5: Rules + correlator
1- creating the rules 
2- creating the colloretor 
## M6: Dashboard
## M7: Demo
EOF
