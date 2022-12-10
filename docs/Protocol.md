# General protocol for authentication, security alerts and file synchronization
## Table
| Message code | Description                                                                                                                                                 | Byte structure                                       | Auth | Alerts | Sync |
|:------------:|-------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------|:----:|:------:|:----:|
|     0001     | Request for server public key. Sent by the eBPF agent to the Manager to request the public key that will be used to authenticate the Manager.               | m_size[4], code[1]                                   | [X]  |  [ ]   | [ ]  |
|     0002     | Response to server public key request. Sent by the Manager to the eBPF agent in response to a request for the server public key, with the key included.     | m_size[4], code[1], key[n]                           | [X]  |  [ ]   | [ ]  |
|     0003     | Request for client public key. Sent by the Manager to the eBPF agent to request the public key that will be used to authenticate the eBPF agent.            | m_size[4], code[1]                                   | [X]  |  [ ]   | [ ]  |
|     0004     | Response to client public key request. Sent by the eBPF agent to the Manager in response to a request for the client public key, with the key included.     | m_size[4], code[1], key[n]                           | [X]  |  [ ]   | [ ]  |
|     0005     | Request for configuration file. Sent by the eBPF agent to the Manager to request the latest version of the configuration file.                              | m_size[4], code[1], ver[n]                           | [ ]  |  [ ]   | [X]  |
|     0006     | Response to configuration file request. Sent by the Manager to the eBPF agent in response to a request for the configuration file, with the latest version. | m_size[4], code[1], ver[n], file[n]                  | [ ]  |  [ ]   | [X]  |
|     0007     | Request for definition file. Sent by the eBPF agent to the Manager to request the latest version of the definition file.                                    | m_size[4], code[1], ver[n]                           | [ ]  |  [ ]   | [X]  |
|     0008     | Response to definition file request. Sent by the Manager to the eBPF agent in response to a request for the definition file, with the latest version.       | m_size[4], code[1], ver[n], file[n]                  | [ ]  |  [ ]   | [X]  |
|     0009     | Suspicious system call alert. Sent by the eBPF agent to the Manager to report a suspicious system call that has been identified.                            | m_size[4], code[1], call[n], pid[4], time[n], sig[n] | [ ]  |  [X]   | [ ]  |
|     0010     | Suspicious process termination. Sent by the Manager to the eBPF agent to request the termination of a suspicious process that has been identified.          | m_size[4], code[1], pid[4], method[n]                | [ ]  |  [X]   | [ ]  |
|     0011     |                                                                                                                                                             |                                                      | [ ]  |  [ ]   | [ ]  |

## Definitions for byte structures
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
