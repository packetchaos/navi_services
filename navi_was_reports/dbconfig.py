import sqlite3
from sqlite3 import Error


def new_db_connection(db_file):
    # create a connection to our database
    conn = None
    try:
        # A database file will be created if one doesn't exist
        conn = sqlite3.connect(db_file, timeout=5.0)
    except Error as E:
        print(E)
    return conn


def create_keys_table():
    # Create Tables
    database = r"navi.db"
    key_conn = new_db_connection(database)
    key_table = """CREATE TABLE IF NOT EXISTS keys (
                            access_key text,
                            secret_key text
                            );"""
    create_table(key_conn, key_table)


def drop_tables(conn, table):
    try:
        drop_table = '''DROP TABLE {}'''.format(table)
        cur = conn.cursor()
        cur.execute('pragma journal_mode=wal;')
        cur.execute(drop_table)
    except Error:
        pass


def create_table(conn, table_information):
    try:
        c = conn.cursor()
        c.execute('pragma journal_mode=wal;')
        c.execute(table_information)
    except Error as e:
        print(e)


def create_apps_table():
    database = r"navi.db"
    app_conn = new_db_connection(database)
    create_apps = """CREATE TABLE IF NOT EXISTS apps (
                            name text,
                            uuid text, 
                            target text, 
                            scan_completed_time text,
                            pages_crawled text,
                            requests_made text, 
                            critical_count text,
                            high_count text,
                            medium_count text,
                            low_count text, 
                            info_count text,
                            owasp text,
                            tech_list text,
                            config_id text,
                            notes text,
                            asset_uuid text
                            );"""
    app_conn.execute('pragma journal_mode=wal;')

    create_table(app_conn, create_apps)


def insert_apps(conn, apps):
    sql = '''INSERT or IGNORE into apps(
             name,
             uuid, 
             target, 
             scan_completed_time,
             pages_crawled,
             requests_made, 
             critical_count,
             high_count,
             medium_count,
             low_count, 
             info_count,
             owasp,
             tech_list,
             config_id,
             notes,
             asset_uuid)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'''
    cur = conn.cursor()
    cur.execute('pragma journal_mode=wal;')
    cur.execute(sql, apps)


def create_plugins_table():
    database = r"navi.db"
    app_conn = new_db_connection(database)
    create_plugins = """CREATE TABLE IF NOT EXISTS plugins (
                            scan_uuid text,
                            name text,
                            cves text,
                            description text, 
                            family text, 
                            output text,
                            owasp text,
                            payload text,
                            plugin_id text,
                            plugin_mod_date text,
                            plugin_pub_date text,
                            proof text,
                            request_headers text,
                            response_headers text,
                            risk_factor text,
                            solution text,
                            url text,
                            xrefs text,
                            see_also text
                            );"""
    app_conn.execute('pragma journal_mode=wal;')

    create_table(app_conn, create_plugins)


def insert_plugins(conn, plugins):
    sql2 = '''INSERT or IGNORE into plugins(
            scan_uuid,
            name,
            cves,
            description, 
            family, 
            output,
            owasp,
            payload,
            plugin_id,
            plugin_mod_date,
            plugin_pub_date,
            proof,
            request_headers,
            response_headers,
            risk_factor,
            solution,
            url,
            xrefs,
            see_also)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'''
    cur2 = conn.cursor()
    cur2.execute('pragma journal_mode=wal;')
    cur2.execute(sql2, plugins)
