import sys
import json
import logging

import pymysql
import boto3
from botocore.exceptions import ClientError


region_name = "ca-central-1"

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def get_secret():

    secret_name = "test/DB/test"


    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise e

    # Decrypts secret using the associated KMS key.
    secret = get_secret_value_response['SecretString']

    return secret


def save_events(event):
    """
	This function fetches content from MySQL RDS instance
	"""
    try:
        credentials = json.loads(get_secret())

        conn = pymysql.connect(
            host=credentials['host'],
            user=credentials['username'],
            passwd=credentials['password'],
            db=credentials['dbname'],
            connect_timeout=5
        )
    except pymysql.MySQLError as e:
        logger.error("ERROR: Unexpected error: Could not connect to MySQL instance.")
        logger.error(e)
        sys.exit()
    else:
        logger.info("SUCCESS: Connection to RDS MySQL instance succeeded")
        result = []

        with conn.cursor() as cur:
            
            insert_stmt = "insert into test (id, name) values(%s, %s)"
            
            records = event['Records']
            
            for record in records:
                body = json.loads(record['body'])
                
                if isinstance(body, dict):
                    id = body["id"]
                    name = body["name"]
                    data = (id, name)
                    cur.execute(insert_stmt, data)
                    conn.commit()
                else:
                    raise Exception("Invalid payload.")
                    
            cur.execute("select * from test")
            for row in cur:
                result.append(list(row))
                    
            logger.info(result)
        conn.commit()

    return "Added %d items from RDS MySQL table" %(len(result))


def main(event, context):
    """
    """
    save_events(event)