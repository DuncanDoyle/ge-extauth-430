# ExtAuth-430 Reproducer

## Installation

Add Gloo EE Helm repo:
```
helm repo add glooe https://storage.googleapis.com/gloo-ee-helm
```

Export your Gloo Edge License Key to an environment variable:
```
export GLOO_EDGE_LICENSE_KEY={your license key}
```

Install Gloo Edge:
```
cd install
./install-gloo-edge-enterprise-with-helm.sh
```

> NOTE
> The Gloo Edge version that will be installed is set in a variable at the top of the `install/install-gloo-edge-enterprise-with-helm.sh` installation script.

## Setup the environment

Run the `install/setup.sh` script to setup the environment:
- Deploy Keycloak
- Deploy the OAuth Authorization Code Flow AuthConfig.
- Deploy the VirtualServices
- Deploy the HTTPBin service

```
./setup.sh
```

Run the `install/k8s-coredns-config.sh` script to patch K8S coreDns service to route `keycloak.example.com` to the Gloo Edge `gateway-proxy`. In this example this is needed to allow the AuthConfig that points to Keycloak to resolve `keycloak.example.com` and to route to Keycloak via the Gateway.

```
./k8s-coredns-config.sh
```

## Setup Keycloak

Run the `keycloak.sh` script to create the OAuth clients and user accounts required to run the demo. This script will create an OAuth client for our web-application to perform OAuth Authorization Code Flow, an OAuth Client (Service Account) for Client Credentials Grant Flow (not used in this example), and 2 user accounts (`user1@example.com` and `user2@solo.io`).

```
./keycloak.sh
```

## Run the test

Access HTTPBin at http://api.example.com/get. You will be redirected to Keycloak. Login with the following credentials:

```
username: user1@example.com
password: password
```

If all is configured correctly, you will be:
- Logged in with Authorization Code Flow.
- A session will be stored in Redis with OAuth `id_token` and `access_token`.
- A session-cookie will be set on the client.
- The `id_token` will be past in a `jwt` header to the Upstream (HTTPBin) service.



## Incorrect AuthConfigs

### Incorrect appUrl

Apply the "incorrect appUrl" `AuthConfig` and default `api-example-com-vs` `VirtualService`:

```
kubectl apply -f policies/extauth/oauth-acf-auth-config-incorrect-appUrl.yaml
kubectl apply -f virtualservices/api-example-com-vs.yaml
```

When redirected to Keycloak, and the "incorrect appUrl" is not set as a valid redirect_uri, you will get the message "Invalid parameter: redirect_uri". Keycloak logs will have the following info:

```
2024-03-18 14:12:49,642 WARN  [org.keycloak.events] (executor-thread-34) type=LOGIN_ERROR, realmId=44570c80-8af3-4ee9-840b-6cf2670ade68, clientId=webapp-client, userId=null, ipAddress=10.244.0.7, error=invalid_redirect_uri, redirect_uri=http://api.example.co/callback
```

When Keycloak does accept the "incorrect appUrl", for example because we're using wildcards, the client simply gets redirected to the wrong callback URL.

Conclusion: Nothing to log in Gateway Proxy or ExtAuth service.

### Incorrect callbackPath

Apply the "incorrect callbackPath" `AuthConfig`:

```
kubectl apply -f policies/extauth/oauth-acf-auth-config-incorrect-callbackPath.yaml
```

Note that for this test we also need to apply a different routetable, one that does not match on `/`:

```
kubectl apply -f virtualservices/api-example-com-vs-incorrect-callbackPath.yaml
```

... and access HTTPBin at: http://api.example.com/httpbin/get


When redirected to Keycloak, and the "incorrect callbackPath" is not set as a valid redirect_uri, you will get the message "Invalid parameter: redirect_uri". Keycloak logs will have the following info:

```
2024-03-18 15:02:02,564 WARN  [org.keycloak.events] (executor-thread-50) type=LOGIN_ERROR, realmId=44570c80-8af3-4ee9-840b-6cf2670ade68, clientId=webapp-client, userId=null, ipAddress=10.244.0.7, error=invalid_redirect_uri, redirect_uri=http://api.example.com/kollback
```

When Keycloak does accept the "incorrect callbackPath", for example because we're using wildcards, the client simply gets redirected to the wrong callback URL.

Conclusion: Same as an incorrect `appUrl` above. Nothing to log in Gateway Proxy or ExtAuth service.

### Incorrect clientId

Apply the "incorrect clientId" `AuthConfig` and default `api-example-com-vs` `VirtualService`:

```
kubectl apply -f policies/extauth/oauth-acf-auth-config-incorrect-clientId.yaml
kubectl apply -f virtualservices/api-example-com-vs.yaml
```

When redirected to Keycloak, and an OAuth client with the id `clientId` set in the `oauth-acf-auth-config-incorrect-clientId` `AuthConfig` is not configured in Keycloak, you will get the message "We are sorry ... Client not found ....". Keycloak logs will have the following info:

```
2024-03-22 20:15:49,796 WARN  [org.keycloak.events] (executor-thread-7) type=LOGIN_ERROR, realmId=44570c80-8af3-4ee9-840b-6cf2670ade68, clientId=webapp-server, userId=null, ipAddress=10.244.0.34, error=client_not_found
```

Conclusion: Nothing to log in the Gateway Proxy or ExtAuth service.


### Incorrect clientSecret

Apply the "incorrect clientSecret" `AuthConfig` and default `api-example-com-vs` `VirtualService`:

```
kubectl apply -f policies/extauth/oauth-acf-auth-config-incorrect-clientSecret.yaml
kubectl apply -f virtualservices/api-example-com-vs.yaml
```

When redirected to Keycloak, and you try to login, the login succeeds, but you will then get a "ERR_TOO_MANY_REDIRECTS" in your browser.

Keycloak will log the following:
```
2024-03-22 20:45:53,393 WARN  [org.keycloak.events] (executor-thread-11) type=CODE_TO_TOKEN_ERROR, realmId=44570c80-8af3-4ee9-840b-6cf2670ade68, clientId=webapp-client, userId=null, ipAddress=10.244.0.34, error=invalid_client_credentials, grant_type=authorization_code
```

The ExtAuth server will log the following:

```
{"level":"error","ts":"2024-03-22T20:45:53Z","logger":"ext-auth.ext-auth-service","msg":"error exchanging token","version":"undefined","x-request-id":"2522d18a-8c38-4523-8c38-d42f0e176e3b","error":"oauth2: \"unauthorized_client\" \"Invalid client or Invalid client credentials\"","stacktrace":"github.com/solo-io/ext-auth-service/pkg/config/oidc.(*CallbackHandler).Callback\n\t/go/pkg/mod/github.com/solo-io/ext-auth-service@v0.55.4-patch3/pkg/config/oidc/callback.go:100\ngithub.com/solo-io/ext-auth-service/pkg/config/oidc.(*CallbackHandler).HandleCallback\n\t/go/pkg/mod/github.com/solo-io/ext-auth-service@v0.55.4-patch3/pkg/config/oidc/callback.go:34\ngithub.com/solo-io/ext-auth-service/pkg/config/oidc.(*RequestAuthorizer).handleCallback\n\t/go/pkg/mod/github.com/solo-io/ext-auth-service@v0.55.4-patch3/pkg/config/oidc/oidc_request.go:605\ngithub.com/solo-io/ext-auth-service/pkg/config/oidc.(*RequestAuthorizer).checkHttpRequestAuthorized\n\t/go/pkg/mod/github.com/solo-io/ext-auth-service@v0.55.4-patch3/pkg/config/oidc/oidc_request.go:486\ngithub.com/solo-io/ext-auth-service/pkg/config/oidc.(*RequestAuthorizer).checkNetworkRequestAuthorized\n\t/go/pkg/mod/github.com/solo-io/ext-auth-service@v0.55.4-patch3/pkg/config/oidc/oidc_request.go:176\ngithub.com/solo-io/ext-auth-service/pkg/config/oidc.(*RequestAuthorizer).areAttributesAuthorized\n\t/go/pkg/mod/github.com/solo-io/ext-auth-service@v0.55.4-patch3/pkg/config/oidc/oidc_request.go:169\ngithub.com/solo-io/ext-auth-service/pkg/config/oidc.(*RequestAuthorizer).CheckRequestAuthorized\n\t/go/pkg/mod/github.com/solo-io/ext-auth-service@v0.55.4-patch3/pkg/config/oidc/oidc_request.go:154\ngithub.com/solo-io/ext-auth-service/pkg/config/oidc.(*IssuerImpl).Authorize\n\t/go/pkg/mod/github.com/solo-io/ext-auth-service@v0.55.4-patch3/pkg/config/oidc/oidc.go:337\ngithub.com/solo-io/ext-auth-service/pkg/chain.(*identityAuthorizerImpl).Authorize\n\t/go/pkg/mod/github.com/solo-io/ext-auth-service@v0.55.4-patch3/pkg/chain/chain.go:389\ngithub.com/solo-io/ext-auth-service/pkg/chain.(*authServiceChain).Authorize\n\t/go/pkg/mod/github.com/solo-io/ext-auth-service@v0.55.4-patch3/pkg/chain/chain.go:120\ngithub.com/solo-io/ext-auth-service/pkg/service.(*authServer).Check\n\t/go/pkg/mod/github.com/solo-io/ext-auth-service@v0.55.4-patch3/pkg/service/extauth.go:150\ngithub.com/envoyproxy/go-control-plane/envoy/service/auth/v3._Authorization_Check_Handler.func1\n\t/go/pkg/mod/github.com/solo-io/go-control-plane-fork-v2@v0.0.0-20231207195634-98d37ef9a43e/envoy/service/auth/v3/external_auth.pb.go:699\ngithub.com/solo-io/go-utils/healthchecker.GrpcUnaryServerHealthCheckerInterceptor.func1\n\t/go/pkg/mod/github.com/solo-io/go-utils@v0.24.8/healthchecker/grpc.go:69\ngoogle.golang.org/grpc.getChainUnaryHandler.func1\n\t/go/pkg/mod/google.golang.org/grpc@v1.59.0/server.go:1163\ngithub.com/solo-io/ext-auth-service/pkg/server.requestIdInterceptor.func1\n\t/go/pkg/mod/github.com/solo-io/ext-auth-service@v0.55.4-patch3/pkg/server/logging.go:86\ngoogle.golang.org/grpc.getChainUnaryHandler.func1\n\t/go/pkg/mod/google.golang.org/grpc@v1.59.0/server.go:1163\ngithub.com/grpc-ecosystem/go-grpc-middleware/logging/zap.UnaryServerInterceptor.func1\n\t/go/pkg/mod/github.com/grpc-ecosystem/go-grpc-middleware@v1.3.0/logging/zap/server_interceptors.go:31\ngoogle.golang.org/grpc.chainUnaryInterceptors.func1\n\t/go/pkg/mod/google.golang.org/grpc@v1.59.0/server.go:1154\ngithub.com/envoyproxy/go-control-plane/envoy/service/auth/v3._Authorization_Check_Handler\n\t/go/pkg/mod/github.com/solo-io/go-control-plane-fork-v2@v0.0.0-20231207195634-98d37ef9a43e/envoy/service/auth/v3/external_auth.pb.go:701\ngoogle.golang.org/grpc.(*Server).processUnaryRPC\n\t/go/pkg/mod/google.golang.org/grpc@v1.59.0/server.go:1343\ngoogle.golang.org/grpc.(*Server).handleStream\n\t/go/pkg/mod/google.golang.org/grpc@v1.59.0/server.go:1737\ngoogle.golang.org/grpc.(*Server).serveStreams.func1.1\n\t/go/pkg/mod/google.golang.org/grpc@v1.59.0/server.go:986"}
```

Logs in Gateway Proxy:
```
[2024-03-22T21:05:24.195Z] "POST /realms/master/protocol/openid-connect/token HTTP/1.1" 401 - 198 98 4 2 "-" "Go-http-client/1.1" "eca984cb-2757-415e-b345-295be9e13d14" "keycloak.example.com" "10.244.0.41:8080"
[2024-03-22T21:05:24.202Z] "POST /realms/master/protocol/openid-connect/token HTTP/1.1" 401 - 251 98 2 1 "-" "Go-http-client/1.1" "f9d3eb78-fc1d-46dc-996a-bf3bb599952f" "keycloak.example.com" "10.244.0.41:8080"
```

We see these logs because the ExtAuth server's token exchange requests flow through the Gateway. So what we see is 401 on the token exchange request from the ExtAuth server to Keycloak.


What basically happens that the token exchange on the ExtAuth server will fail, as the ExtAuth server is using the incorrect `CLIENT_SECRET`. The ExtAuth server will still redirect the client to the original URL, on which the client is again redirected to Keycloak, as there is no valid token. Since we're already logged in to Keycloakwhere we are already logged in, redirecting the client back to the `callbackUrl` where the token exchange fails, 


Conclusion: Both the logs in the ExtAuth server and Keycloak are pretty clear here. The logs in ExtAuth clearly say that we have either an invalid client or invalid credentials. The logs in Keycloak clearly say that the client credentials are invalid. So, also here, I don't think there is much extra logging needed. What we could do is to show the actual request that is being fired to Keycloak when we set the ExtAuth server's logging to DEBUG.

### Incorrect clientSecretRef

Apply the "incorrect clientSecretRef" `AuthConfig` and default `api-example-com-vs` `VirtualService`:

```
kubectl apply -f policies/extauth/oauth-acf-auth-config-incorrect-clientSecretRef.yaml
kubectl apply -f virtualservices/api-example-com-vs.yaml
```

When redirected trying to access http://api.example.com/get, you will be immediately denied access with a `HTTP ERROR 403`.

The logs of the ExtAuth-Server show that there is no configuration with the given id (`gloo.system.oauth-acf-auth`):

```
{"level":"error","ts":"2024-03-25T08:35:56Z","logger":"ext-auth.ext-auth-service","msg":"Auth Server does not contain auth configuration with the given ID","version":"undefined","x-request-id":"dffd2f6a-d33f-49c5-bc21-0ff3e3fe8639","RequestContext":{"AuthConfigId":"gloo-system.oauth-acf-auth","SourceType":"virtual_host","SourceName":"gloo-system.gateway-proxy-listener-::-8080-gloo-system_vs"},"stacktrace":"github.com/solo-io/ext-auth-service/pkg/service.(*authServer).Check\n\t/go/pkg/mod/github.com/solo-io/ext-auth-service@v0.55.4-patch3/pkg/service/extauth.go:142\ngithub.com/envoyproxy/go-control-plane/envoy/service/auth/v3._Authorization_Check_Handler.func1\n\t/go/pkg/mod/github.com/solo-io/go-control-plane-fork-v2@v0.0.0-20231207195634-98d37ef9a43e/envoy/service/auth/v3/external_auth.pb.go:699\ngithub.com/solo-io/go-utils/healthchecker.GrpcUnaryServerHealthCheckerInterceptor.func1\n\t/go/pkg/mod/github.com/solo-io/go-utils@v0.24.8/healthchecker/grpc.go:69\ngoogle.golang.org/grpc.getChainUnaryHandler.func1\n\t/go/pkg/mod/google.golang.org/grpc@v1.59.0/server.go:1163\ngithub.com/solo-io/ext-auth-service/pkg/server.requestIdInterceptor.func1\n\t/go/pkg/mod/github.com/solo-io/ext-auth-service@v0.55.4-patch3/pkg/server/logging.go:86\ngoogle.golang.org/grpc.getChainUnaryHandler.func1\n\t/go/pkg/mod/google.golang.org/grpc@v1.59.0/server.go:1163\ngithub.com/grpc-ecosystem/go-grpc-middleware/logging/zap.UnaryServerInterceptor.func1\n\t/go/pkg/mod/github.com/grpc-ecosystem/go-grpc-middleware@v1.3.0/logging/zap/server_interceptors.go:31\ngoogle.golang.org/grpc.chainUnaryInterceptors.func1\n\t/go/pkg/mod/google.golang.org/grpc@v1.59.0/server.go:1154\ngithub.com/envoyproxy/go-control-plane/envoy/service/auth/v3._Authorization_Check_Handler\n\t/go/pkg/mod/github.com/solo-io/go-control-plane-fork-v2@v0.0.0-20231207195634-98d37ef9a43e/envoy/service/auth/v3/external_auth.pb.go:701\ngoogle.golang.org/grpc.(*Server).processUnaryRPC\n\t/go/pkg/mod/google.golang.org/grpc@v1.59.0/server.go:1343\ngoogle.golang.org/grpc.(*Server).handleStream\n\t/go/pkg/mod/google.golang.org/grpc@v1.59.0/server.go:1737\ngoogle.golang.org/grpc.(*Server).serveStreams.func1.1\n\t/go/pkg/mod/google.golang.org/grpc@v1.59.0/server.go:986"}
```

It does not state that the client-secret is incorrect, but when we look at the given `AuthConfig`:

```
kubectl -n gloo-system get authconfig oauth-acf-auth -o yaml
```

We can see that the configuration has been rejected because it can't find the client secret:

```
status:
  statuses:
    gloo-system:
      reason: "1 error occurred:\n\t* failed to translate ext auth config: client
        secret expected and not found\n\n"
      reportedBy: gloo
      state: Rejected
```

Conclusion: The logging of the ExtAuth-Server shows that the given `AuthConfig` can't be found. When inspecting the `AuthConfig`, the status clearly states that there is a problem with the client secret configuration. I don't think we can log much more than that.


### Incorrect issuerUrl

Apply the "incorrect issuerUrl" `AuthConfig` and default `api-example-com-vs` `VirtualService`:

```
kubectl apply -f policies/extauth/oauth-acf-auth-config-incorrect-issuerUrl.yaml
kubectl apply -f virtualservices/api-example-com-vs.yaml
```

When redirected trying to access http://api.example.com/get, you will be immediately denied access with a `HTTP ERROR 403`.


ExtAuth-Server logging shows that the issues URL can't be found: `issuer discovery failed - failed with code 404 Not Found`:

```
{"level":"error","ts":"2024-03-25T09:02:42.900Z","caller":"discovery/discovery.go:137","msg":"can't parse issuer's discovery document","version":"1.16.4","error":"request failed with code 404 Not Found","stacktrace":"github.com/solo-io/ext-auth-service/pkg/config/oidc/discovery.Discover\n\t/go/pkg/mod/github.com/solo-io/ext-auth-service@v0.55.4-patch3/pkg/config/oidc/discovery/discovery.go:137\ngithub.com/solo-io/ext-auth-service/pkg/config/oidc.(*IssuerImpl).Discover\n\t/go/pkg/mod/github.com/solo-io/ext-auth-service@v0.55.4-patch3/pkg/config/oidc/oidc.go:246\ngithub.com/solo-io/ext-auth-service/pkg/config/oidc.(*IssuerImpl).Start\n\t/go/pkg/mod/github.com/solo-io/ext-auth-service@v0.55.4-patch3/pkg/config/oidc/oidc.go:173\ngithub.com/solo-io/ext-auth-service/pkg/chain.(*authServiceChain).Start\n\t/go/pkg/mod/github.com/solo-io/ext-auth-service@v0.55.4-patch3/pkg/chain/chain.go:110\ngithub.com/solo-io/solo-projects/projects/extauth/pkg/config.(*configGenerator).GenerateConfig.func1\n\t/go/src/github.com/solo-io/solo-projects/projects/extauth/pkg/config/generator.go:135"}
{"level":"error","ts":"2024-03-25T09:02:42.901Z","caller":"oidc/oidc.go:259","msg":"error during discovery","version":"1.16.4","error":"request failed with code 404 Not Found","stacktrace":"github.com/solo-io/ext-auth-service/pkg/config/oidc.(*IssuerImpl).Discover\n\t/go/pkg/mod/github.com/solo-io/ext-auth-service@v0.55.4-patch3/pkg/config/oidc/oidc.go:259\ngithub.com/solo-io/ext-auth-service/pkg/config/oidc.(*IssuerImpl).Start\n\t/go/pkg/mod/github.com/solo-io/ext-auth-service@v0.55.4-patch3/pkg/config/oidc/oidc.go:173\ngithub.com/solo-io/ext-auth-service/pkg/chain.(*authServiceChain).Start\n\t/go/pkg/mod/github.com/solo-io/ext-auth-service@v0.55.4-patch3/pkg/chain/chain.go:110\ngithub.com/solo-io/solo-projects/projects/extauth/pkg/config.(*configGenerator).GenerateConfig.func1\n\t/go/src/github.com/solo-io/solo-projects/projects/extauth/pkg/config/generator.go:135"}
{"level":"error","ts":"2024-03-25T09:02:42.902Z","caller":"oidc/oidc.go:176","msg":"issuer discovery failed","version":"1.16.4","error":"request failed with code 404 Not Found","stacktrace":"github.com/solo-io/ext-auth-service/pkg/config/oidc.(*IssuerImpl).Start\n\t/go/pkg/mod/github.com/solo-io/ext-auth-service@v0.55.4-patch3/pkg/config/oidc/oidc.go:176\ngithub.com/solo-io/ext-auth-service/pkg/chain.(*authServiceChain).Start\n\t/go/pkg/mod/github.com/solo-io/ext-auth-service@v0.55.4-patch3/pkg/chain/chain.go:110\ngithub.com/solo-io/solo-projects/projects/extauth/pkg/config.(*configGenerator).GenerateConfig.func1\n\t/go/src/github.com/solo-io/solo-projects/projects/extauth/pkg/config/generator.go:135"}
{"level":"error","ts":"2024-03-25T09:02:42.902Z","caller":"config/generator.go:136","msg":"Error calling Start function","version":"1.16.4","error":"request failed with code 404 Not Found","authConfig":"gloo-system.oauth-acf-auth","stacktrace":"github.com/solo-io/solo-projects/projects/extauth/pkg/config.(*configGenerator).GenerateConfig.func1\n\t/go/src/github.com/solo-io/solo-projects/projects/extauth/pkg/config/generator.go:136"}
{"level":"error","ts":"2024-03-25T09:02:42.913Z","caller":"discovery/discovery.go:137","msg":"can't parse issuer's discovery document","version":"1.16.4","error":"request failed with code 404 Not Found","stacktrace":"github.com/solo-io/ext-auth-service/pkg/config/oidc/discovery.Discover\n\t/go/pkg/mod/github.com/solo-io/ext-auth-service@v0.55.4-patch3/pkg/config/oidc/discovery/discovery.go:137\ngithub.com/solo-io/ext-auth-service/pkg/config/oidc.(*IssuerImpl).Discover\n\t/go/pkg/mod/github.com/solo-io/ext-auth-service@v0.55.4-patch3/pkg/config/oidc/oidc.go:246\ngithub.com/solo-io/ext-auth-service/pkg/config/oidc.(*IssuerImpl).Start.func1\n\t/go/pkg/mod/github.com/solo-io/ext-auth-service@v0.55.4-patch3/pkg/config/oidc/oidc.go:185"}
{"level":"error","ts":"2024-03-25T09:02:42.913Z","caller":"oidc/oidc.go:259","msg":"error during discovery","version":"1.16.4","error":"request failed with code 404 Not Found","stacktrace":"github.com/solo-io/ext-auth-service/pkg/config/oidc.(*IssuerImpl).Discover\n\t/go/pkg/mod/github.com/solo-io/ext-auth-service@v0.55.4-patch3/pkg/config/oidc/oidc.go:259\ngithub.com/solo-io/ext-auth-service/pkg/config/oidc.(*IssuerImpl).Start.func1\n\t/go/pkg/mod/github.com/solo-io/ext-auth-service@v0.55.4-patch3/pkg/config/oidc/oidc.go:185"}
{"level":"error","ts":"2024-03-25T09:02:42.913Z","caller":"oidc/oidc.go:187","msg":"issuer discovery failed","version":"1.16.4","error":"request failed with code 404 Not Found","stacktrace":"github.com/solo-io/ext-auth-service/pkg/config/oidc.(*IssuerImpl).Start.func1\n\t/go/pkg/mod/github.com/solo-io/ext-auth-service@v0.55.4-patch3/pkg/config/oidc/oidc.go:187"}
```

This error is shown when the configuration is applied.

When you visit http://api.example.com/get, you will get a 500 error.

Note that the ExtAuth policy is accepted by Gloo.

The main problem here is that the Error log of the ExtAuth server can get buried. On the actual authorization requests, you will get the following message:

```
2024-03-25T12:38:10.533Z	DEBUG	ext-auth.ext-auth-service	Received auth request	{"version": "undefined", "x-request-id": "2f387ac7-2e7f-492c-8756-433f6c73b972", "request": {"attributes": {"source": {"address":{"Address":{"SocketAddress":{"address":"10.244.0.1","PortSpecifier":{"PortValue":56776}}}}}, "destination": {"address":{"Address":{"SocketAddress":{"address":"10.244.0.34","PortSpecifier":{"PortValue":8080}}}}}, "context_extensions": {"config_id":"gloo-system.oauth-acf-auth","source_name":"gloo-system.gateway-proxy-listener-::-8080-gloo-system_vs","source_type":"virtual_host"}, "request": {"time": "2024-03-25T12:38:10.527Z", "http": {"body": "", "host": "api.example.com", "fragment": "", "method": "GET", "path": "/get", "scheme": "http", "size": 0, "query": "", "protocol": "HTTP/1.1", "id": "17606814726595044002", "headers": {"accept-language": "en-US,en;q=0.5", "accept-encoding": "gzip, deflate", "dnt": "1", ":scheme": "http", "upgrade-insecure-requests": "1", "sec-gpc": "1", "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:124.0) Gecko/20100101 Firefox/124.0", ":authority": "api.example.com", ":path": "/get", ":method": "GET", "x-request-id": "2f387ac7-2e7f-492c-8756-433f6c73b972", "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", "x-forwarded-proto": "http"}}}}}}
2024-03-25T12:38:10.535Z	DEBUG	ext-auth.ext-auth-service	Access denied by auth authService	{"version": "undefined", "x-request-id": "2f387ac7-2e7f-492c-8756-433f6c73b972", "authService": "config_0"}
```

... and nothing more. And since the AuthConfig has been accepted, there is nothing that tells you that there actually is a problem with the config, apart from the first time you deploy it.

Conclusion: When the `issuerUrl` is misconfigured, this is only logged once, when the `AuthConfig` is deployed, and this log line easily gets buried. All requests after this are denied by the ExtAuth server, but you can't tell why. Because the `AuthConfig` is accepted, this is quite hard to debug. When we deny access because of this kind of misconfiguration, we need to show this in the, at least, the debug logging (but maybe even error logging ...).

### Incorrect DiscoveryOverride AuthEndpoint

Apply the "incorrect DiscoveryOverride AuthEndpoint" `AuthConfig` and default `api-example-com-vs` `VirtualService`:

```
kubectl apply -f policies/extauth/oauth-acf-auth-config-incorrect-discoveryOverride-authendpoint.yaml
kubectl apply -f virtualservices/api-example-com-vs.yaml
```

When redirected trying to access http://api.example.com/get, you will be redirected to the wrong authEndpoint in Keycloak, which will show a "We are sorry - Page not found" error.

The ExtAuth logging shows the incorrect URL in the logging, although it's of course not logged as an error, because ExtAuth does not know if the Auth Endpoint we've configured is correct or not.

Conclusion: No extra logging needed. Nothing to log in Gateway Proxy or ExtAuth service.


### Incorrect DiscoveryOverride AuthEndpoint

Apply the "incorrect DiscoveryOverride AuthEndpoint" `AuthConfig` and default `api-example-com-vs` `VirtualService`:

```
kubectl apply -f policies/extauth/oauth-acf-auth-config-incorrect-discoveryOverride-tokenendpoint.yaml
kubectl apply -f virtualservices/api-example-com-vs.yaml
```

When redirected trying to access http://api.example.com/get, you will be redirected to the correct Keycloak login page. After logging in, the callback in ExtAuth Server is unable to access the correct token endpoint and hence is not able to exchange the access code for the access-token and identity-token. You will get the following error in the ExtAuth server:

```
2024-03-25T14:47:00.161Z	ERROR	ext-auth.ext-auth-service	error exchanging token	{"version": "undefined", "x-request-id": "c1533261-12f7-4ed1-901c-9bfb919b2206", "error": "oauth2: \"RESTEASY003210: Could not find resource for full path: http://keycloak.example.com/realms/master/protocol/openid-connect/toke\""}
```

This is logged on every token exchange attempt.

Conclusion: No extra logging needed. ExtAuth server logs a token exchange error on every attempt.


## Conclusion
This demonstrates how to secure the HTTPBin sample application using Authorization Code Flow with Gloo Edge and Keycloak. The goal of this reproducer is to make the OAuth `oidcAuthorizationCode` AuthConfig fail (incorrect URLs, incorrect `clientId` and `clientSecret`) to understand where we need to improve logging to make these authN/authZ failures easier to debug.

