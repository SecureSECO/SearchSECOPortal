# SearchSECOPortal
The code for the SearchSECO portal.

## Required tokens
To run the portal there should be a `keys.json` file with the `grafana_token` and `github_token`. You also need to generate the gmail tokens. To do this first run `node auth.js`. This will give a link where you need to log in with the gmail account to send mail from. This will give a link with a code. Copy this code and paste it in token.js. After this run `node token.js` to generate the tokens.
In order to work with https you also need to make sure there are the `key.pem` and `cert.pem` files.

## Running the portal
To run the portal you shpuld first build the docker image: `docker build -t portal-image .`. After this you can run the portal using
```
docker run --name portal -d -p 443:8000 -v /var/run/docker.sock:/var/run/docker.sock --restart=always portal-image
```
