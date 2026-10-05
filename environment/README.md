# Certificate Authority Project
Applied Security Lab  
Group 13



## Docker Images & Kathara Network

The Prebuilt-Images directory contains .tar-files **pre-built Docker images** for all the containers. 

The system consists of seven docker images: 
- **client**
- the servers: 
    - **webserver**
    - **authserver**
    - **caserver**
    - **logserver**
- the firewalls: 
    - **fw1**
    - **fw2**

The `lab.conf` file contains the **Kathara** configurations of the network.  
Please refer to the description and the diagram in the report for details on how the system is structured and what each component's function is. 


## Starting the System
Create your private local configuration before the first run:

```bash
cp .env.example .env
# Replace every placeholder in .env with a strong local value.
```

The `.env` file is ignored by Git. Never commit it. The provided `start.sh`
and `start.ps1` scripts validate the required variables and pass them to the
isolated lab containers.

Start the system by running `start.sh` (Linux / Mac) or `start.ps1` (Windows). 

Connect to the individual machines with `kathara connect <servername>`.
For the client, you can connect with noVNC: `http://localhost:6080`.

To access the system's services, connect to `https://webserver`

Stop running the containers using `kathara lclean`.


## Lab credentials

SSH and database credentials are configured locally in `.env`. They are
intended only for this isolated teaching environment and must not be reused
for real systems.


## Source Code & Config locations

- App source code: `/var/www/<servername>/` 
- Nginx configuration: `/etc/nginx/sites-available/<servername>`

for `servername` in `webserver`, `authserver`, `caserver`, `logserver`


## User Database
The user database is located on the **Authserver**.  
It contains synthetic users from `Images/authserver/seed_users.sql`.
The user with uid `ps` is the CA admin; the others are regular users.
The admin login certificate is generated at runtime and placed at `/` on the
client machine. A helper script for creating `.p12` files is also available.
