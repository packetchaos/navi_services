import getpass
from database import new_db_connection
from dbconfig import create_keys_table, create_diff_table, create_assets_table, create_vulns_table, create_compliance_table, create_passwords_table


def keys(access_key, secret_key):
    # create all Tables when keys are added.
    create_keys_table()
    create_diff_table()
    create_vulns_table()
    create_assets_table()
    create_compliance_table()
    create_passwords_table()

    key_dict = (access_key, secret_key)
    database = r"navi.db"
    conn = new_db_connection(database)

    with conn:
        sql = '''INSERT or IGNORE into keys(access_key, secret_key) VALUES(?,?)'''
        cur = conn.cursor()
        cur.execute(sql, key_dict)
