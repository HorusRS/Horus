# Authentication and Security Protocol for eBPF Agents protocol for authentication, security alerts and file synchronization
This file is the documentation of the general protocol to be used in the eBPF agent and the server

The protocol will allow for:
- Authenticating the agents and the server
- E2E Encryption
- Alerts about suspicious events
- Synchronization of configuration files

## Key features and steps
1. Agents are running on port 2222, Server is running on port 2121
	- The agents are running first and wait for a message from the server
	- The server runs after being told what agents are available and sends them the first message (next step)
2. Server makes the first message and Authenticates the agent
	- Server will authenticate the agent using the public key
3. Agents are authenticating the server
	- Agents will authenticate the server by the public key as well
4. Server syncs the configuration and settings files
	- The server makes sure that the orders the user has defined on the server side
	are known to the agents before they start their actions
5. Server tells the agents to start running
	- The end of the predictable parts
* From here the agents will pass alerts and information as needed to the server
and the server will send messages only for killing the agent or updating files or settings


## Table and definitions
| Message code | Description                                                                                                                                                 | Byte structure                                       | Auth                  | Alerts                | Sync                  | Manual actions        |
|:------------:|-------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------|:---------------------:|:---------------------:|:---------------------:|:---------------------:|
|     0001     | Request for server public key. Sent by the eBPF agent to the server to request the public key that will be used to authenticate the server.                 | m_size[4], code[1]                                   |<ul><li> [x] </li></ul>|<ul><li> [ ] </li></ul>|<ul><li> [ ] </li></ul>|<ul><li> [ ] </li></ul>|
|     0002     | Response to server public key request. Sent by the server to the eBPF agent in response to a request for the server public key, with the key included.      | m_size[4], code[1], key[n]                           |<ul><li> [x] </li></ul>|<ul><li> [ ] </li></ul>|<ul><li> [ ] </li></ul>|<ul><li> [ ] </li></ul>|
|     0003     | Request for client public key. Sent by the server to the eBPF agent to request the public key that will be used to authenticate the eBPF agent.             | m_size[4], code[1]                                   |<ul><li> [x] </li></ul>|<ul><li> [ ] </li></ul>|<ul><li> [ ] </li></ul>|<ul><li> [ ] </li></ul>|
|     0004     | Response to client public key request. Sent by the eBPF agent to the server in response to a request for the client public key, with the key included.      | m_size[4], code[1], key[n]                           |<ul><li> [x] </li></ul>|<ul><li> [ ] </li></ul>|<ul><li> [ ] </li></ul>|<ul><li> [ ] </li></ul>|
|     0005     | Request for configuration file. Sent by the server to the eBPF agent to request the latest version of the configuration file.                               | m_size[4], code[1], ver[n]  file[n]                  |<ul><li> [ ] </li></ul>|<ul><li> [ ] </li></ul>|<ul><li> [x] </li></ul>|<ul><li> [ ] </li></ul>|
|     0006     | Response to configuration file request. Sent by the eBPF agent to the server in response to a request for the configuration file, with the latest version.  | m_size[4], code[1], ver[n],                          |<ul><li> [ ] </li></ul>|<ul><li> [ ] </li></ul>|<ul><li> [x] </li></ul>|<ul><li> [ ] </li></ul>|
|     0007     | Request for definition file. Sent by the eBPF agent to the server to request the latest version of the definition file.                                     | m_size[4], code[1], ver[n]                           |<ul><li> [ ] </li></ul>|<ul><li> [ ] </li></ul>|<ul><li> [x] </li></ul>|<ul><li> [ ] </li></ul>|
|     0008     | Response to definition file request. Sent by the server to the eBPF agent in response to a request for the definition file, with the latest version.        | m_size[4], code[1], ver[n], file[n]                  |<ul><li> [ ] </li></ul>|<ul><li> [ ] </li></ul>|<ul><li> [x] </li></ul>|<ul><li> [ ] </li></ul>|
|     0009     | Suspicious system call alert. Sent by the eBPF agent to the server to report a suspicious system call that has been identified.                             | m_size[4], code[1], call[n], pid[4], time[n], sig[n] |<ul><li> [ ] </li></ul>|<ul><li> [x] </li></ul>|<ul><li> [ ] </li></ul>|<ul><li> [ ] </li></ul>|
|     0010     | Request for stop signal. Sent by the server to the eBPF agent to request that the agent stop working.                                                       | m_size[4], code[1]                                   |<ul><li> [ ] </li></ul>|<ul><li> [ ] </li></ul>|<ul><li> [ ] </li></ul>|<ul><li> [x] </li></ul>|
|     0011     | Response to stop signal request. Sent by the eBPF agent to the server in response to a request to stop working, indicating success.                         | m_size[4], code[1]                                   |<ul><li> [ ] </li></ul>|<ul><li> [ ] </li></ul>|<ul><li> [ ] </li></ul>|<ul><li> [x] </li></ul>|

### Definitions for byte structures
* m_size : The size of the entire message, in bytes, excluding the size of the m_size field itself (i.e. the total number of bytes in the message, minus 4 bytes).
* code   : The message code number, which is used to identify the type of message that is being sent.
* key    : The public key that is being exchanged as part of the authentication process.
* ver    : The version number of the configuration or definition file that is being requested or sent.
* file   : The actual content of the configuration or definition file.
* call   : The name of the suspicious system call that has been identified by the eBPF agent.
* pid    : The process ID of the process that is making the suspicious system call or that is being targeted for termination.
* time   : The time and date at which the suspicious system call was made or the process was terminated.
* sig    : The signature of the suspicious system call, as defined in the definition file.
* method : The method by which the suspicious process will be terminated (e.g. "kill", "terminate", etc.).
