![My Image](Logo.png)
# Horus
Horus is an open-source tool for running forensic and administrative tasks at the kernel level using eBPF,
a low-overhead in-kernel virtual machine, and the Rust programming language.

# tl;dr
This project will result in a tool that will allow you to block certain actions on your systems.
Some are dangerous like tracing programs and fileless execution, Some are stupid like running `rm -rf .` when you are in your home directory (true story)
Think of it as a firewall on the kernel level. you're welcome!

# How to run?
- run kwall?
> `kwall run serverless / full`

- run kcontroller?
> `kcontroller run`

- run the ELK stack?
> `docker-compose up`
