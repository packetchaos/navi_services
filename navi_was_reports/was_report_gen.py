from flask import Flask, render_template, request
from dbconfig import insert_apps, create_apps_table, new_db_connection, drop_tables, create_keys_table, create_plugins_table, insert_plugins
import requests
import dateutil.parser
import datetime
import time
import sys
app = Flask(__name__)


def grab_headers():
    header_db = r"navi.db"
    h_conn = new_db_connection(header_db)
    with h_conn:
        h_cur = h_conn.cursor()
        h_cur.execute("SELECT * from keys;")
        rows = h_cur.fetchall()
        for row in rows:
            access_key = row[0]
            secret_key = row[1]
    return {'Content-type': 'application/json', 'user-agent': 'Navi-WAS-Reporter', 'X-ApiKeys': 'accessKey=' + access_key + ';secretKey=' + secret_key}


def request_data(method, url_mod, **kwargs):

    # set the Base URL
    url = "https://cloud.tenable.com"

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

    # Retry the request three times
    for x in range(1, 3):
        try:
            r = requests.request(method, url + url_mod, headers=grab_headers(), params=params, json=payload, verify=True)
            if r.status_code == 200:
                return r.json()
            else:
                print("Something went wrong...Don't be trying to hack me now {}".format(r))
                break
        except ConnectionError:
            print("Check your connection...You got a connection error. Retying")
            continue


def plugin_parser(plugin_output):
    tech_list = []
    # Split the plugin information on '-'
    plugin_tuple = plugin_output.split('-')
    # Ignore the item in the tuple and add all others to a list
    for x in range(len(plugin_tuple) - 1):
        tech_list.append(str(plugin_tuple[x + 1]))
    return tech_list


def vuln_counter(plugin_id, scan_uuid):
    database = r"navi.db"
    conn = new_db_connection(database)
    with conn:
        cur = conn.cursor()
        cur.execute("SELECT count(*) from plugins where plugin_id =='{}' and scan_uuid=='{}';".format(plugin_id, scan_uuid))

        plugin_data = cur.fetchall()

        return plugin_data[0][0]


def download_data(uuid, asset):
    database = r"navi.db"
    app_conn = new_db_connection(database)
    app_conn.execute('pragma journal_mode=wal;')
    with app_conn:
        apps_table_list = []
        report = request_data('GET', '/was/v2/scans/{}/report'.format(uuid))
        #scan_metadata = get_was_stats(uuid)

        config_id = report['config']['config_id']

        # Ignore all scans that have not completed
        if report['scan']['status'] == 'completed':
            scan_name = report['config']['name']

            scan_completed_time = report['scan']['finalized_at']
            try:
                requests_made = 0#scan_metadata['requests_made']
            except KeyError:
                requests_made = 0

            try:
                pages_crawled = 0#scan_metadata['crawler_requests']
            except KeyError:
                pages_crawled = 0

            critical = []
            high = []
            medium = []
            low = []
            info = []
            critical_summary = []
            high_summary = []
            medium_summary = []
            low_summary = []
            info_summary = []
            tech_list = []
            owasp_list = []
            owasp_dict = {}
            try:
                notes = report['config']['notes']
            except KeyError:
                notes = "No Scan Notes"

            try:
                target = report['scan']['target']
            except KeyError:
                target = report['config']['settings']['target']

            # Count for-loop
            plugin_list = []

            for finding in report['findings']:
                plugin_list.append(finding['plugin_id'])
                for xref in finding['xrefs']:
                    # Grab multiples values here
                    if xref['xref_name'] == 'OWASP':
                        if '2021' in xref['xref_value']:
                            owasp_clean = str(xref['xref_value']).split('-')[1]
                            owasp_list.append(owasp_clean)

            def occurances(number, number_list):
                return number_list.count(number)

            for owasp in range(1, 11):
                owasp_dict["A{}".format(owasp)] = occurances("A{}".format(owasp), owasp_list)

            for finding in report['findings']:
                finding_list = []
                risk = finding['risk_factor']
                plugin_id = finding['plugin_id']
                plugin_name = finding['name']
                family = finding['family']
                cves = finding['cves']
                description = finding['description']
                output = finding['output']
                owasp = finding['owasp']
                payload = finding['payload']
                plugin_mod_date = finding['plugin_modification_date']
                plugin_pub_date = finding['plugin_publication_date']
                proof = finding['proof']
                request_headers = finding['request_headers']
                response_headers = finding['response_headers']
                solution = finding['solution']
                url = finding['uri']
                xrefs = finding['xrefs']
                see_also = finding['see_also']

                finding_list.append(str(uuid))
                finding_list.append(str(plugin_name))
                finding_list.append(str(cves))
                finding_list.append(str(description))
                finding_list.append(str(family))
                finding_list.append(str(output))
                finding_list.append(str(owasp))
                finding_list.append(str(payload))
                finding_list.append(str(plugin_id))
                finding_list.append(str(plugin_mod_date))
                finding_list.append(str(plugin_pub_date))
                finding_list.append(str(proof))
                finding_list.append(str(request_headers))
                finding_list.append(str(response_headers))
                finding_list.append(str(risk))
                finding_list.append(str(solution))
                finding_list.append(str(url))
                finding_list.append(str(xrefs))
                finding_list.append(str(see_also))

                insert_plugins(app_conn, finding_list)

                if str(plugin_id) == '98059':
                    tech_list = plugin_parser(finding['output'])

                vuln_count = occurances(finding['plugin_id'], plugin_list)
                vuln_list = [risk, plugin_id, plugin_name, family, vuln_count]
                if risk == 'high':
                    high.append(plugin_id)
                    if vuln_list not in high_summary:
                        high_summary.append(vuln_list)
                elif risk == 'medium':
                    medium.append(plugin_id)
                    if vuln_list not in medium_summary:
                        medium_summary.append(vuln_list)
                elif risk == 'low':
                    low.append(plugin_id)
                    if vuln_list not in low_summary:
                        low_summary.append(vuln_list)
                elif risk == 'critical':
                    critical.append(plugin_id)
                    if vuln_list not in critical_summary:
                        critical_summary.append(vuln_list)
                else:
                    info.append(plugin_id)
                    if vuln_list not in info_summary:
                        info_summary.append(vuln_list)

            apps_table_list.append(scan_name)
            apps_table_list.append(uuid)
            apps_table_list.append(target)
            apps_table_list.append(scan_completed_time)
            apps_table_list.append(pages_crawled)
            apps_table_list.append(requests_made)
            apps_table_list.append(len(critical))
            apps_table_list.append(len(high))
            apps_table_list.append(len(medium))
            apps_table_list.append(len(low))
            apps_table_list.append(len(info))
            apps_table_list.append(str(owasp_dict))
            apps_table_list.append(str(tech_list))
            apps_table_list.append(config_id)
            apps_table_list.append(str(notes))
            apps_table_list.append(str(asset))

            insert_apps(app_conn, apps_table_list)

    return


def grab_scans(days):
    database = r"navi.db"
    app_conn = new_db_connection(database)
    app_conn.execute('pragma journal_mode=wal;')

    drop_tables(app_conn, 'apps')
    create_apps_table()
    create_plugins_table()

    data = request_data('POST', '/was/v2/configs/search?limit=200&offset=0')

    for configs in data['items']:
        config_id = configs['config_id']
        was_config_data = request_data("POST", "/was/v2/configs/{}/scans/search".format(config_id))
        # Ignore all scans that have not completed

        for scanids in was_config_data['items']:

            day = 86400
            new_limit = day * int(days)
            day_limit = time.time() - new_limit

            if scanids['status'] == 'completed': # and scanids['template_name'] == 'scan':
                try:
                    asset_uuid = scanids['asset_id']
                except KeyError:
                    asset_uuid = "NO ID Found"
                try:
                    uri = scanids['application_uri']
                except KeyError:
                    uri = "NOPE"

                if uri != "NOPE":
                    was_scan_id = scanids['scan_id']
                    finalized_at = scanids['finalized_at']
                    try:
                        epoch = datetime.datetime.strptime(finalized_at, "%Y-%m-%dT%H:%M:%S.%fZ").timestamp()

                        if epoch >= day_limit:

                            download_data(was_scan_id, asset_uuid)
                    except TypeError:
                        pass
            else:
                pass

    return


@app.route('/report')
def scan_report():
    scan_uuid = request.args.get('scan_uuid')
    database = r"navi.db"
    conn = new_db_connection(database)
    app_data = {}
    with conn:
        cur = conn.cursor()
        cur2 = conn.cursor()
        cur.execute("SELECT * from plugins where scan_uuid =='{}';".format(scan_uuid))
        cur2.execute("SELECT * from apps where uuid=='{}';".format(scan_uuid))
        plugin_data = cur.fetchall()
        data2 = cur2.fetchall()

        critical_summary = []
        high_summary = []
        medium_summary = []
        low_summary = []
        info_summary = []
        tech_list = []
        owasp_list = []

        critical = []
        high = []
        medium = []
        low = []
        info = []
        info2 = []

        scan_name = data2[0][0]
        asset_uuid = data2[0][15]
        scan_completed_time = data2[0][3]
        requests_made = data2[0][5]
        pages_crawled = data2[0][4]
        target = data2[0][2]
        notes = data2[0][14]
        plugin_list = []
        instance_dict = {}
        sitemap = 'No Sitemap Found'
        plugin_info_list = {}

        for finding in plugin_data:

            owasp_dict = []
            plugin_id = finding[8]

            # This list is to count plugins
            plugin_list.append(plugin_id)

            instance_dict.setdefault(plugin_id, []).append(finding[16])

            def occurances(number, number_list):
                return number_list.count(number)

            if str(plugin_id) == '98059':
                tech_list = plugin_parser(finding[5])

            if str(plugin_id) == '98009':
                sitemap = finding[5]

            if str(plugin_id) == '98000':
                scan_stats = finding[5]

            plugin_name = finding[1]
            family = finding[4]
            description = finding[3]
            see_also = eval(finding[18])
            solution = finding[15]
            owasp_list = finding[6]
            risk = finding[14]
            proof = finding[11]


            for year in eval(owasp_list):
                if year['year'] == '2021':
                    owasp_dict.append(year['category'])

            vuln_count = vuln_counter(plugin_id, scan_uuid) #occurances(plugin_id, plugin_list)

            vuln_list = [risk, plugin_id, plugin_name, family, owasp_dict, vuln_count]

            if plugin_id not in plugin_info_list:
                plugin_info_list[plugin_id] = [risk, family, description, see_also, solution, instance_dict[plugin_id], proof]

            if risk == 'high':
                high.append(plugin_id)
                if vuln_list not in high_summary:
                    high_summary.append(vuln_list)
            elif risk == 'medium':
                medium.append(plugin_id)
                if vuln_list not in medium_summary:
                    medium_summary.append(vuln_list)
            elif risk == 'low':
                low.append(plugin_id)
                if vuln_list not in low_summary:
                    low_summary.append(vuln_list)
            elif risk == 'critical':
                critical.append(plugin_id)
                if vuln_list not in critical_summary:
                    critical_summary.append(vuln_list)
            else:
                info.append(plugin_id)
                if vuln_list not in info_summary:
                    info_summary.append(vuln_list)

        return render_template('was_report.html', scan_name=scan_name, scan_completed_time=scan_completed_time,
                               requests_made=requests_made, pages_crawled=pages_crawled,
                               critical=len(critical), high=len(high), target=target, low=len(low), medium=len(medium),
                               name=scan_name, scan_uuid=scan_uuid, info=len(info), high_summary=high_summary,
                               medium_summary=medium_summary, low_summary=low_summary, info_summary=info_summary,
                               critical_summary=critical_summary, tech_list=tech_list, notes=notes,
                               owasp_dict=owasp_dict, scan_stats=scan_stats,
                               sitemap=sitemap[:-116], plugin_info_list=plugin_info_list, asset_uuid=asset_uuid)


@app.route('/')
def consolidated():
    config_id = request.args.get('config_id')
    scan_summaries = []

    data = request_data('POST', '/was/v2/configs/search?limit=200&offset=0')
    for scan_data in data['items']:
        if scan_data['last_scan']:
            try:
                was_scan_id = scan_data['last_scan']['scan_id']
                status = scan_data['last_scan']['status']
                # Ignore all scans that have not completed
                if status == 'completed':
                    scan_summary = []
                    summary_start = scan_data['last_scan']['started_at']
                    finish = scan_data['last_scan']['finalized_at']
                    application = scan_data['last_scan']['application_uri']
                    scan_summary.append(application)
                    scan_summary.append(was_scan_id)
                    scan_summary.append(summary_start)
                    scan_summary.append(finish)
                    scan_summaries.append(scan_summary)
            except KeyError:
                # If there is a Key error it is due to a Parent record
                pass

    # grab data from the Database
    critical_total, high_total, medium_total, low_total, info_total, crawled_total, request_total, \
    app_data, value_dict, technology_list = grab_was_consolidated_data(config_id)

    # Send the data to the Web Page
    return render_template('was_consolidated_report.html', scan_summaries=scan_summaries, crawled_total=crawled_total,
                           critical_total=critical_total,
                           high_total=high_total, medium_total=medium_total, low_total=low_total,
                           request_total=request_total, info_total=info_total, app_data=app_data, value_dict=value_dict,
                           technology_list=set(technology_list))


def grab_was_consolidated_data(config_id):
    database = r"navi.db"
    conn = new_db_connection(database)
    app_data = {}
    with conn:
        cur = conn.cursor()
        if config_id:
            cur.execute("SELECT critical_count, high_count, medium_count, low_count, info_count,"
                        "pages_crawled, requests_made, target, uuid, name, owasp, tech_list, scan_completed_time, config_id from apps where config_id='{}';".format(config_id))
        else:
            cur.execute("SELECT critical_count, high_count, medium_count, low_count, info_count,"
                        "pages_crawled, requests_made, target, uuid, name, owasp, tech_list, scan_completed_time, config_id from apps;")

        data = cur.fetchall()

        # Set baselines for calculating totals
        critical_total = 0
        high_total = 0
        medium_total = 0
        low_total = 0
        info_total = 0
        crawled_total = 0
        request_total = 0
        owasp_list = []
        values_per_key = {}
        value_dict = {}
        technology_list = []

        for apps in data:
            scan_completed_time_raw = apps[12]
            scan_completed_time_formatted = dateutil.parser.parse(scan_completed_time_raw)
            scan_completed_time = scan_completed_time_formatted.strftime("%A, %b %-d %Y")

            # Totals
            critical_total = critical_total + int(apps[0])
            high_total = high_total + int(apps[1])
            medium_total = medium_total + int(apps[2])
            low_total = low_total + int(apps[3])
            info_total = info_total + int(apps[4])
            crawled_total = crawled_total + int(apps[5])
            request_total = request_total + int(apps[6])

            # Values
            critical = apps[0]
            high = apps[1]
            medium = apps[2]
            low = apps[3]
            info = apps[4]
            pages_crawled = apps[5]
            requests_made = apps[6]
            target = apps[7]
            scan_uuid = apps[8]
            scan_name = apps[9]
            owasp_dictionary = apps[10]
            tech_dictionary = apps[11]
            scan_config = apps[13]

            app_data[apps[8]] = [critical, high, medium, low, info,
                                 pages_crawled, requests_made, target, scan_name, eval(owasp_dictionary),
                                 eval(tech_dictionary), scan_completed_time, scan_uuid, scan_config]

            # owasp info is saved a json format as a string. Turn it into a dict using eval
            owasp_dict = eval(apps[10])

            # Create a list of owasp dicts for display iteration and calculations
            owasp_list.append(owasp_dict)

            # turn the tech list string into a list, cycle through each tech in the list.
            for tech in eval(apps[11]):

                # check to see if the current tech is a duplicate, before adding it to the global list
                if tech not in technology_list:
                    technology_list.append(tech)

        # This code counts the values of every dict and uses that information to create a new dictionary.
        for instance in owasp_list:
            for risk, value in instance.items():
                # Group each value with its corresponding Key
                values_per_key.setdefault(risk, []).append(value)
                # Cycle through each key and add them up
                for owasp_risk, risk_value in values_per_key.items():
                    total = 0  # Set the value to zero
                    for val in risk_value:
                        total = total + val
                        value_dict[owasp_risk] = total

        return critical_total, high_total, medium_total, low_total, info_total, crawled_total, request_total, app_data, value_dict, technology_list


def run_app():
    app.run(host="0.0.0.0", port=5004)


if __name__ == '__main__':
    print("\n This is going to take a few minutes.\n Downloading all of your completed scans\n")
    create_keys_table()
    init_access_key = sys.argv[1]
    init_secret_key = sys.argv[2]
    try:
        limit_days = int(sys.argv[3])
    except:
        limit_days = 60
    key_dict = (init_access_key, init_secret_key)
    navi_database = r"navi.db"
    init_conn = new_db_connection(navi_database)
    with init_conn:
        sql = '''INSERT or IGNORE into keys(access_key, secret_key) VALUES(?,?)'''
        cur = init_conn.cursor()
        cur.execute(sql, key_dict)
        drop_tables(init_conn, 'apps')
        drop_tables(init_conn, 'plugins')
    grab_scans(limit_days)
    run_app()

