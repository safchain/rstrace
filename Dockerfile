FROM python:3.9.18-slim

COPY main /wrapper
COPY init.sh /init.sh
COPY webapp.py /webapp.py

CMD /wrapper /init.sh
