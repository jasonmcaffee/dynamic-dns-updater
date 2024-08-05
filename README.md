# Dynamic DNS Updater
This project uses python libraries for tp-link routers and cloudflare to periodically update my self hosted websites with my latest WAN ip address.

# Setup
## .env file
create a .env file in the project's root directory, with the following entries
### TP_LINK_ROUTER_PASSWORD=2x2lcallingcq
The password you use to log into your tp link router

e.g. `TP_LINK_ROUTER_PASSWORD=password`

### CLOUDFLARE_GLOBAL_KEY
The global key (not access token) from cloudflare.

e.g. `CLOUDFLARE_GLOBAL_KEY="77739439023dkkls89858ed"`

### CLOUDFLARE_EMAIL
The email address you use with cloudflare.

e.g `CLOUDFLARE_EMAIL=somebody@gmail.com`

### Example .env
``` 
TP_LINK_ROUTER_PASSWORD=password
CLOUDFLARE_GLOBAL_KEY="12345ad"
CLOUDFLARE_EMAIL=somebody@gmail.com
```

# Run

## Windows
``` 
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

## Linux & Mac
```
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py
```