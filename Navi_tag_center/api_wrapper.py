import requests
import click
from sqlite3 import Error
from json import JSONDecodeError
from database import new_db_connection
from tenable.io import TenableIO


def navi_version():
    return "navi-6.9.1"


def tenb_connection():
    try:
        access_key = '0'
        secret_key = '0'
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT * from keys;")
            rows = cur.fetchall()
            for row in rows:
                access_key = row[0]
                secret_key = row[1]

            # Check for custom URL
            try:
                cur.execute("SELECT * from url;")
                url_rows = cur.fetchall()
                url = url_rows[0][1]
                tio = TenableIO(access_key, secret_key, url=url, vendor='Casey Reid', product='navi', build=navi_version())
                return tio
            except Error:
                tio = TenableIO(access_key, secret_key, vendor='Casey Reid', product='navi', build=navi_version())
                return tio

    except Error:
        pass


def grab_url():
    database = r"navi.db"
    conn = new_db_connection(database)
    with conn:
        cur = conn.cursor()
        try:
            cur.execute("SELECT * from url;")
            rows = cur.fetchall()
            url = rows[0][1]
        except Error:
            url = 'https://cloud.tenable.com'
    return url


def grab_headers():
    access_key = '0'
    secret_key = '0'
    database = r"navi.db"
    conn = new_db_connection(database)
    with conn:
        cur = conn.cursor()
        try:
            cur.execute("SELECT * from keys;")
        except Error:
            pass
        rows = cur.fetchall()
        for row in rows:
            access_key = row[0]
            secret_key = row[1]
    return {'Content-type': 'application/json', 'user-agent': navi_version(), 'X-ApiKeys': 'accessKey=' + access_key + ';secretKey=' + secret_key}


def request_data(method, url_mod, **kwargs):

    # set the Base URL
    url = grab_url()

    # check for params and set to None if not found
    try:
        params = kwargs['params']
    except KeyError:
        params = None

    # check for a payload and set to None if not found
    try:
        payload = kwargs['payload']
    except KeyError:
        payload = None

    # Retry the download three times
    for x in range(1, 3):
        try:
            r = requests.request(method, url + url_mod, headers=grab_headers(), params=params, json=payload, verify=True)
            return r
        except ConnectionError:
            click.echo("Check your connection...You got a connection error. Retying")
            continue
        except JSONDecodeError:
            click.echo("Download Error or User enabled / Disabled ")
            continue
