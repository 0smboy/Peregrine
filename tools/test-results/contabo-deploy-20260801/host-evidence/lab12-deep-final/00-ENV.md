{
  "swift_base": "http://127.0.0.1:8080",
  "shadow_peer_base": "http://127.0.0.1:8090",
  "shadow_peer_auth": "http://127.0.0.1:8090/auth/v1.0",
  "shadow_peer_label": "Python SAIO",
  "lab_enabled": true
}
shadow_peer_config_ok
http://10.0.0.10:8085/healthcheck 200
http://127.0.0.1:8090/healthcheck 200
http://127.0.0.1:8081/healthcheck 200
