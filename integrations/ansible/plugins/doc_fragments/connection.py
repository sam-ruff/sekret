class ModuleDocFragment:
    DOCUMENTATION = r"""
options:
  url:
    description:
      - Base URL of the sekret server, for example C(https://sekret.example.com).
      - Required, either here or through E(SEKRET_URL).
    type: str
    env:
      - name: SEKRET_URL
  project:
    description:
      - Project slug or ID.
    type: str
    env:
      - name: SEKRET_PROJECT
  environment:
    description:
      - Environment slug within the project, for example C(prod).
    type: str
    env:
      - name: SEKRET_ENVIRONMENT
  path:
    description:
      - Folder path holding the secrets.
    type: str
    default: /
  auth_method:
    description:
      - How to authenticate.
      - V(auto) uses the first of O(token), O(client_id) and O(client_secret),
        or O(identity_id) with an OIDC token.
      - V(kubernetes) is never picked automatically and has to be asked for.
      - Defaults to V(auto).
    type: str
    choices: [auto, token, universal, oidc, kubernetes]
    env:
      - name: SEKRET_AUTH_METHOD
  token:
    description:
      - A bearer token to use as is, such as one from C(sekret admin bootstrap) or a machine login.
    type: str
    env:
      - name: SEKRET_TOKEN
  client_id:
    description:
      - Client ID of a machine identity using universal auth.
    type: str
    env:
      - name: SEKRET_CLIENT_ID
  client_secret:
    description:
      - Client secret paired with O(client_id).
    type: str
    env:
      - name: SEKRET_CLIENT_SECRET
  identity_id:
    description:
      - ID of the machine identity for OIDC and Kubernetes auth.
    type: str
    env:
      - name: SEKRET_IDENTITY_ID
  oidc_token:
    description:
      - An OIDC JWT to exchange for a sekret token.
    type: str
    env:
      - name: SEKRET_OIDC_TOKEN
  oidc_token_file:
    description:
      - File holding an OIDC JWT. Used when O(oidc_token) is not set.
    type: path
    env:
      - name: SEKRET_OIDC_TOKEN_FILE
  kubernetes_token_file:
    description:
      - Service account token file used with O(auth_method=kubernetes). Required for that method.
      - Use a projected token with the C(sekret) audience, never the pod's default
        C(/var/run/secrets/kubernetes.io/serviceaccount/token), which also works against the Kubernetes API.
    type: path
    env:
      - name: SEKRET_KUBERNETES_TOKEN_FILE
  validate_certs:
    description:
      - Whether to verify the server's TLS certificate. Defaults to V(true).
    type: bool
    env:
      - name: SEKRET_VALIDATE_CERTS
  ca_path:
    description:
      - CA bundle file, or directory of hashed certificates, used to verify the server.
      - Use this when the server certificate comes from a private CA.
    type: path
    env:
      - name: SEKRET_CA_PATH
  client_cert:
    description:
      - PEM client certificate presented to servers or proxies that require mutual TLS.
      - Requires O(client_key).
    type: path
    env:
      - name: SEKRET_CLIENT_CERT
  client_key:
    description:
      - PEM private key for O(client_cert).
    type: path
    env:
      - name: SEKRET_CLIENT_KEY
  timeout:
    description:
      - Seconds to wait for each HTTP request. Defaults to 30.
    type: float
    env:
      - name: SEKRET_TIMEOUT
notes:
  - Machine logins are cached per process and per set of credentials, so many lookups in one task log in once.
"""
