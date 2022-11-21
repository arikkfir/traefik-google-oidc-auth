# traefik-google-oidc-auth

![Maintainer](https://img.shields.io/badge/maintainer-arikkfir-blue)
![GoVersion](https://img.shields.io/github/go-mod/go-version/arikkfir/traefik-google-oidc-auth.svg)
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/arikkfir/traefik-google-oidc-auth)
[![GoReportCard](https://goreportcard.com/badge/github.com/arikkfir/traefik-google-oidc-auth)](https://goreportcard.com/report/github.com/arikkfir/traefik-google-oidc-auth)
[![codecov](https://codecov.io/gh/arikkfir/traefik-google-oidc-auth/branch/main/graph/badge.svg?token=QP3OAILB25)](https://codecov.io/gh/arikkfir/traefik-google-oidc-auth)

## About

This is a Traefik middleware that allows you to authenticate users using Google's OpenID Connect.

General flow of authentication is like so:
1. User sends request to https://app.example.com
2. Traefik receives the request and forwards it to the middleware
   - This is because the `IngressRoute` of the application lists this middleware in the `middlewares` field
3. Middleware checks if the user is authenticated by checking a cookie for the `example.com` domain
   - Middleware is able to search for the cookie because Traefik forwards the request and all its headers, including
     the `Cookie` header, to the middleware
4. If the user is not authenticated (no cookie), the middleware redirects the user to Google's OpenID Connect login page
5. User logs in to Google
6. Google redirects the user back to the OAuth app's redirect URL https://oauth.example.com/callback
   - You will specify that redirect URL when you create the OAuth client ID (the "OAuth App") in Google Cloud
   - You will also create an `IngressRoute` in Traefik that forwards requests to that hostname to the middleware
7. The plugin will verify the authentication, and if valid, will store a cookie for `example.com` with the user's email
8. The plugin will redirect the user back to the original URL that was requested (e.g. https://app.example.com/welcome)

## Deploying

### Create an OAuth application

In order to protect your application with Google OAuthm, you will need to create an OAuth client ID. This is essentially
a set of credentials that will represent your application, and for which Google will ask the user to
provide their Email address once authenticate.

1. Go to the [APIs & Services → Credentials](https://console.cloud.google.com/apis/credentials) page in your Google Cloud project.
2. Create an OAuth client ID:
   1. Click the "CREATE CREDENTIALS" button
   2. Select "OAuth client ID"
   3. Select "Web application"
   4. Enter a name for the OAuth client ID (e.g. "My App")
   5. Under "Authorized redirect URIs", enter the URL in your Traefik instance that will receive the callback redirect
      from Google after the user has authenticated (e.g. `https://oauth.example.com/callback`)
      * The URL path **_MUST_** be `/callback`
   6. Click "CREATE".
3. Save the client ID and client secret from the OAuth client ID you just created.
   * For this tutorial, let's assume you saved the client ID and client secret in the `client_id.txt` & `client_secret.txt` files respectively.

### Deploy the plugin

Now we will install the plugin in the cluster. We will assume that you've already have Traefik set up and running in
your cluster, with the Kubernetes CRD provider enabled.

#### Create a Kubernetes secret with the OAuth client ID and secret

```shell
$ kubectl create secret generic my-app-oauth \
            --from-file=client_id=client_id.txt \
            --from-file=client_secret=client_secret.txt \
            --from-literal=hashing_secret=SUPER_DUPER_SECRET_VALUE
```

#### Create a `values.yaml` file

```yaml
oauth:
  clientId:
    secretName: my-app-oauth  # Name of the secret you created in the previous step
    key: client_id            # Key in the secret that contains the client ID
  clientSecret:
    secretName: my-app-oauth  # Name of the secret you created in the previous step 
    key: client_secret        # Key in the secret that contains the client secret
  host: oauth.example.com     # Hostname to which Google will redirect to after successful authentication
security:
  userCookie:
    name: X-Example-Auth      # Name of the cookie to store authentication information in
    domain: .example.com      # Domain to set the cookie for - must be a parent domain for both the OAuth callback and your application
  hashingSecret:
    secretName: my-app-oauth  # Name of the secret you created in the previous step
    key: hashing_secret       # Key in the secret that contains the hashing secret
  allowedDomains:             # List of domains that are allowed to authenticate
    - example.com
```

#### Install the Helm chart

```bash
$ helm repo add arikkfir https://arikkfir.github.io/charts
$ help install arikkfir/traefik-google-oidc-auth --values values.yaml
```

### Configuration

#### Plugin resources

```yaml
apiVersion: traefik.containo.us/v1alpha1
kind: Middleware
metadata:
  name: google-auth
spec:
  forwardAuth:
    address: http://traefik-google-oidc-auth-server:80/verify # Cluster-internal service URL of the plugin
    trustForwardHeader: true
    authResponseHeaders:
      - Set-Cookie
---
apiVersion: traefik.containo.us/v1alpha1
kind: IngressRoute
metadata:
  name: oauth-plugin-https
spec:
  entryPoints: [websecure]
  routes:
    - kind: Rule
      match: Host(`oauth.example.com`)  # Hostname that you configured in values.yaml file
      services:
        - kind: Service
          name: traefik-google-oidc-auth-server # Cluster-internal service URL of the plugin
          port: http
  tls:
    secretName: oauth-example-com-tls # TLS is required, make sure you set it up (use Let's Encrypt!)
```

#### Application resources

```yaml
apiVersion: traefik.containo.us/v1alpha1
kind: IngressRoute
metadata:
  name: my-app-https
spec:
  entryPoints: [websecure]
  routes:
    - kind: Rule
      match: Host(`app.example.com`)
      middlewares:
        - name: google-auth   # The middleware you set up above
          namespace: traefik
      services:
         - kind: Service
           name: my-app
           namespace: my-app
           port: http
  tls:
    secretName: my-app-example-com-tls
```

## Development

### Setup

Assumptions:
- Git is available as `git`
- Go is available as `go` and `GOPATH` is set to outside of the project directory (not a parent of it!)
- The `$GOPATH/bin` directory is part of your `$PATH` environment variable.

```shell
$ git clone https://github.com/arikkfir/traefik-google-oidc-auth.git
$ cd traefik-google-oidc-auth
$ go mod download
```

### Running

```shell
$ go vet ./...
$ go test ./...
```
