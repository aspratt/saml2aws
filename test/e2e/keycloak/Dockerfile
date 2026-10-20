FROM quay.io/keycloak/keycloak:26.0
COPY --chown=keycloak:root .work/realm.json /opt/keycloak/data/import/e2e-realm.json
ENTRYPOINT ["/opt/keycloak/bin/kc.sh", "start-dev", "--import-realm", "--http-port=8080", "--health-enabled=true"]
