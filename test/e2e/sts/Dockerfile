# moto stands in for AWS STS. It answers as sts.amazonaws.com (and the regional
# names) on the e2e network with a certificate from the throwaway test CA.
FROM motoserver/moto:5.0.28
COPY --chmod=0644 .work/certs/sts.crt .work/certs/sts.key /certs/
ENTRYPOINT ["moto_server", "-H", "0.0.0.0", "-p", "443", "-c", "/certs/sts.crt", "-k", "/certs/sts.key"]
