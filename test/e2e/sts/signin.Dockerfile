FROM motoserver/moto:5.0.28
COPY --chmod=0644 .work/certs/sts.crt .work/certs/sts.key sts/signin.py /srv/
ENTRYPOINT ["python3", "/srv/signin.py", "/srv/sts.crt", "/srv/sts.key"]
