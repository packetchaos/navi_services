import click
from th_asset_export import asset_export
from th_vuln_export import vuln_export
from th_compliance_export import compliance_export
from database import new_db_connection, drop_tables, create_table


def threads_check(threads):
    if threads != 10:  # Limit the amount of threads to avoid issues
        click.echo("\nUsing {} thread(s) at your request".format(threads))
        if threads not in range(1, 11):
            click.echo("Enter a value between 1 and 10")
            exit()


def update():
    pass


def full(threads):

    if threads:
        threads_check(threads)

    exid = '0'

    vuln_export(30, exid, threads)
    asset_export(90, exid, threads)


def assets(threads, days, exid):
    if threads:
        threads_check(threads)

    if exid == ' ':
        exid = '0'

    asset_export(days, exid, threads)


def vulns(threads, days, exid):
    if threads:
        threads_check(threads)

    if exid == ' ':
        exid = '0'

    vuln_export(days, exid, threads)


def compliance(threads, days, exid):
    if threads:
        threads_check(threads)

    if exid == ' ':
        exid = '0'

    compliance_export(days, exid, threads)


def fixed(c, v, days):
    fixed_export(c, v, days)


def url(new_url):

    database = r"navi.db"
    conn = new_db_connection(database)
    drop_tables(conn, 'url')
    create_url_table = """CREATE TABLE IF NOT EXISTS url (name text, url text);"""
    create_table(conn, create_url_table)

    info = ("Custom URL", new_url)
    with conn:
        sql = '''INSERT or IGNORE into url (name, url) VALUES(?,?)'''
        cur = conn.cursor()
        cur.execute(sql, info)
