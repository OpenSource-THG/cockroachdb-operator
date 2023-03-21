import kubernetes 
import tempfile
import psycopg
import logging
import secrets
import string
import base64
import kopf
import os

def getK8sApi():
    kubernetes.config.load_incluster_config()
    return kubernetes.client.CoreV1Api()

def getCockroachCertificates(api, cert_secret_name, cert_secret_namespace):
    secret = api.read_namespaced_secret(cert_secret_name, cert_secret_namespace)
    certificate_files = {}
    for key, data in secret.data.items():
        try:
            certificate_files[key] = writeToTempFile(base64.b64decode(data))
        except Exception as e:
            deleteFiles(certificate_files.values())
            raise e
    return certificate_files

def deleteFiles(files):
    for file in files:
        deleteFile(file)

def deleteFile(file):
    try:
        os.remove(file)
    except Exception as e:
        print(f"Could not delete file due to {e}")

def b64e(str):
    return base64.b64encode(str.encode()).decode()

def b64d(str):
    return base64.b64decode(str.encode()).decode()

def writeToTempFile(content):
    fd, tmpfile = tempfile.mkstemp()
    with open(tmpfile, 'wb') as f:
        try:
            f.write(content)
        except Exception as e:
            deleteFile(tmpfile)
            raise e
    return tmpfile

def createCockroachConnection(api, host, cert_secret_name, cert_secret_namespace):
    certificate_files = getCockroachCertificates(api, cert_secret_name, cert_secret_namespace)
    cockroach_conn = psycopg.connect(f"host={host} port=26257 user=root dbname=defaultdb sslmode=verify-full sslcert={certificate_files['tls.crt']} sslkey={certificate_files['tls.key']} sslrootcert={certificate_files['ca.crt']}",
    application_name="crdb-operator")
    cockroach_conn.autocommit = True
    deleteFiles(certificate_files.values())
    return cockroach_conn

def getConnectionInfo(body, spec):
    namespace = body['metadata']['namespace']
    return {
      "host": spec.get("cockroachServiceName", f"cockroachdb-public.{namespace}"),
      "certSecretName": spec.get("cockroachRootSecret", "cockroachdb-root"),
      "certSecretNamespace": namespace
    }

def generatePassword(password_length = 18):
    alphabet = string.ascii_letters + string.digits
    return ''.join([secrets.choice(alphabet) for i in range(password_length)])

def getCredentialsSecret(api, secret_name, secret_namespace):
    try:
        return api.read_namespaced_secret(secret_name, secret_namespace)
    except kubernetes.client.exceptions.ApiException as e:
        if e.status == 404:
            return None
        else:
            raise e

def createCredentialsSecret(api, secret_name, secret_namespace):
    body = kubernetes.client.V1Secret()
    body.api_version = 'v1'
    body.data = {}
    body.kind = 'Secret'
    body.metadata = {'name': secret_name}
    body.type = 'Opaque'
    try:   
        api.create_namespaced_secret(secret_namespace, body)
    except kubernetes.client.exceptions.ApiException as e:
        if e.status != 409:
            raise e

def setCredentialsSecret(api, secret_name, secret_namespace, data):
    body = api.read_namespaced_secret(secret_name, secret_namespace)
    body.data = data
    api.replace_namespaced_secret(secret_name, secret_namespace, body)

def getCockroachUserCredentials(api, secret_name, secret_namespace, username, user_key, password_key):
    secret = getCredentialsSecret(api, secret_name, secret_namespace)
    if secret == None:
        createCredentialsSecret(api, secret_name, secret_namespace)
        secret_data = {}
    else:
        secret_data = secret.data or {}
    secret_username = secret_data.get(user_key, None)
    secret_password = secret_data.get(password_key, None)
    if secret_password == None or secret_username == None or secret_username != username:
        secret_password = secret_data.get(password_key, generatePassword())
        data = {
            user_key: b64e(username),
            password_key: b64e(secret_password)
        }
        setCredentialsSecret(api, secret_name, secret_namespace, data)
    return {
        "username": username, 
        "password": secret_password
    }

def listUsers(cockroach_conn):
    users = cockroach_conn.execute(f"WITH U AS (SHOW USERS) SELECT username FROM U;")
    return [u[0] for u in users.fetchall()]

def listDatabases(cockroach_conn):
    databases = cockroach_conn.execute(f"WITH D AS (SHOW DATABASES) SELECT database_name FROM D;")
    return [t[0] for t in databases.fetchall()]

def listTables(cockroach_conn, database):
    tables = cockroach_conn.execute(f"WITH T AS (SHOW TABLES FROM \"{database}\") SELECT table_name FROM T;")
    return [t[0] for t in tables.fetchall()]
    
def createCockroachUser(api, cockroach_conn, spec, body):
    credentials_secret_name = spec['credentialsSecret']
    credentials_secret_namespace = body['metadata']['namespace']
    credentials_username = body['metadata']['name']
    credentials_user_key = spec.get("credentialsSecretUsernameKey", "COCKROACHDB_USERNAME")
    credentials_password_key = spec.get("credentialsSecretPasswordKey", "COCKROACHDB_PASSWORD")
    cockroach_user_creds = getCockroachUserCredentials(api, credentials_secret_name, credentials_secret_namespace, credentials_username, credentials_user_key, credentials_password_key)
    try:
        cockroach_conn.execute(f"CREATE USER IF NOT EXISTS \"{cockroach_user_creds['username']}\";")
        cockroach_conn.execute(f"ALTER USER \"{cockroach_user_creds['username']}\" WITH PASSWORD '{cockroach_user_creds['password']}';")
    except psycopg.errors.SyntaxError as e:
        raise Exception("Syntax error when creating user")

def deleteCockroachUser(cockroach_conn, cockroach_username):
    cockroach_conn.execute(f"DROP USER \"{cockroach_username}\";")

def grantDatabasePermissions(cockroach_conn, grants, user):
    for grant in grants:
        cockroach_conn.execute(f"GRANT {grant['grant']} ON DATABASE \"{grant['database']}\" TO \"{user}\";")

def revokeDatabasePermissions(cockroach_conn, grants, user):
    for grant in grants:
        cockroach_conn.execute(f"REVOKE {grant['grant']} ON DATABASE \"{grant['database']}\" FROM \"{user}\";")

def grantTablePermissions(cockroach_conn, grants, user):
    databases = set([grant["database"] for grant in grants])
    tables = {database: listTables(cockroach_conn, database) for database in databases}
    for grant in grants:
        if len(tables.get(grant['database'], [])) > 0:
            if (grant['table'] == "*"):
                cockroach_conn.execute(f"GRANT {grant['grant']} ON TABLE \"{grant['database']}\".{grant['table']} TO \"{user}\";")
            else:
                cockroach_conn.execute(f"GRANT {grant['grant']} ON TABLE \"{grant['database']}\".\"{grant['table']}\" TO \"{user}\";")

def revokeTablePermissions(cockroach_conn, grants, user):
    databases = set([grant["database"] for grant in grants])
    tables = {database: listTables(cockroach_conn, database) for database in databases}
    for grant in grants:
        if len(tables.get(grant['database'], [])) > 0:
            if (grant['table'] == "*"):
                cockroach_conn.execute(f"REVOKE {grant['grant']} ON TABLE \"{grant['database']}\".{grant['table']} FROM \"{user}\";")
            else:
                cockroach_conn.execute(f"REVOKE {grant['grant']} ON TABLE \"{grant['database']}\".\"{grant['table']}\" FROM \"{user}\";")

def revokeAllPermissions(cockroach_conn, user):
    databases = [d for d in listDatabases(cockroach_conn) if not d == "system"]
    for database in databases:
        tables = listTables(cockroach_conn, database)
        cockroach_conn.execute(f"REVOKE ALL ON DATABASE \"{database}\" FROM \"{user}\";")
        if len(tables) > 0:
            cockroach_conn.execute(f"REVOKE ALL ON TABLE \"{database}\".* FROM \"{user}\";")

@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_):
   settings.peering.standalone = True
   settings.posting.level = logging.INFO

@kopf.on.create('cockroachdb.ics.cloud', 'v1', 'database', errors=kopf.ErrorsMode.TEMPORARY) 
def kopfCreateDatabase(body, spec, **kwargs):
    api = getK8sApi()
    ci = getConnectionInfo(body, spec)
    with createCockroachConnection(api, ci['host'], ci['certSecretName'], ci['certSecretNamespace']) as cockroach_conn:
        try:
            cockroach_conn.execute(f"CREATE DATABASE \"{body['metadata']['name']}\"")
        except psycopg.errors.DuplicateDatabase as e:
            kopf.info(body, reason='Success', message='Database already exists')
        kopf.info(body, reason='Success', message='Database created successfully')

@kopf.on.create('cockroachdb.ics.cloud', 'v1', 'user', errors=kopf.ErrorsMode.TEMPORARY) 
def kopfCreateUser(body, spec, **kwargs):
    api = getK8sApi()
    ci = getConnectionInfo(body, spec)
    with createCockroachConnection(api, ci['host'], ci['certSecretName'], ci['certSecretNamespace']) as cockroach_conn:
        credentials_username = body['metadata']['name']
        createCockroachUser(api, cockroach_conn, spec, body)
        grantDatabasePermissions(cockroach_conn, spec.get("databaseGrants", {}), credentials_username)
        grantTablePermissions(cockroach_conn, spec.get("tableGrants", {}), credentials_username)
        kopf.info(body, reason='Success', message='User created successfully')

@kopf.on.update('cockroachdb.ics.cloud', 'v1', 'user', errors=kopf.ErrorsMode.TEMPORARY)
def kopfUpdateUser(body, meta, spec, status, old, new, diff, **kwargs):
    diff_dict = {}
    for spec, diff in { '.'.join(i[1]): {"old": i[2], "new": i[3]} for i in diff }.items():
        diff_dict[spec] = {
            "add": [x for x in diff['new'] if x not in diff['old']],
            "remove": [x for x in diff['old'] if x not in diff['new']]
        }
    api = getK8sApi()
    ci = getConnectionInfo(body, body.spec)
    db_username = body['metadata']['name']
    with createCockroachConnection(api, ci['host'], ci['certSecretName'], ci['certSecretNamespace']) as cockroach_conn:
        if len(diff_dict["spec.databaseGrants"]["remove"]) > 0:
            revokeDatabasePermissions(cockroach_conn, diff_dict["spec.databaseGrants"]["remove"], db_username)
        if len(diff_dict["spec.tableGrants"]["remove"]) > 0:
            revokeTablePermissions(cockroach_conn, diff_dict["spec.tableGrants"]["remove"], db_username)
        if len(diff_dict["spec.databaseGrants"]["add"]) > 0:
            grantDatabasePermissions(cockroach_conn, diff_dict["spec.databaseGrants"]["add"], db_username)
        if len(diff_dict["spec.tableGrants"]["add"]) > 0:
            grantTablePermissions(cockroach_conn, diff_dict["spec.tableGrants"]["add"], db_username)
        kopf.info(body, reason='Success', message='User updated successfully')

@kopf.on.delete('cockroachdb.ics.cloud', 'v1', 'user', errors=kopf.ErrorsMode.TEMPORARY) 
def kopfDeleteUser(body, spec, **kwargs):
    api = getK8sApi()
    ci = getConnectionInfo(body, spec)
    with createCockroachConnection(api, ci['host'], ci['certSecretName'], ci['certSecretNamespace']) as cockroach_conn:
        credentials_secret_name = spec['credentialsSecret']
        credentials_secret_namespace = body['metadata']['namespace']
        credentials_username = body['metadata']['name']
        if (credentials_username in listUsers(cockroach_conn)):
            revokeAllPermissions(cockroach_conn, credentials_username)
            deleteCockroachUser(cockroach_conn, credentials_username)
            api.delete_namespaced_secret(credentials_secret_name, credentials_secret_namespace)
            kopf.info(body, reason='Success', message='User deleted successfully')
        kopf.info(body, reason='Success', message='User does not exist')