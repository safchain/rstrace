FROM ubuntu:22.04
RUN apt-get update && apt-get install -y python3 dnsutils

COPY init.sh /init.sh
COPY webapp.py /webapp.py

COPY --from=safchain/dd-cws-wrapper /dd-cws-wrapper /dd-cws-wrapper
CMD /dd-cws-wrapper --log-level debug /init.sh
