FROM python:3.11-slim
RUN mkdir /operator
ADD crdb_operator.py /operator
RUN pip install kopf==1.36.0 kubernetes==6.1.0 psycopg-binary==3.1.8
CMD kopf run --liveness=http://0.0.0.0:8080/healthz /operator/crdb_operator.oy