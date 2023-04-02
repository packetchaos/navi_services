from flask import Flask, render_template, request, url_for, redirect
import sqlite3
from sqlite3 import Error
import locale, time
from database import new_db_connection, drop_tables, db_query, insert_rules
from dbconfig import create_table, create_rules_table
import json
import base64
import uuid
import subprocess
from os import system as sys
import os
from api_wrapper import tenb_connection, request_data
from keys import keys
import datetime
#from dynamic_rules import run_rules_now
#locale.setlocale(locale.LC_ALL, 'en_US.utf-8')

starttime = time.time()

app = Flask(__name__)

tio = tenb_connection()


def grab_hop_count(uuid):
    # grab the output of 10287 - Trace Route
    hop_count_data = db_query("select output from vulns where asset_uuid='{}' and plugin_id='10287';".format(uuid))

    # Send the raw data back
    return hop_count_data


def average_by_policy(scan_info):
    average_dict = {}
    # Cycle through each category
    for scan in scan_info.items():

        # data is in a list [asset_uuid, mins] We need the length of the total mins found
        length = len(scan[1])

        # Reset the total per Category Item - Specific Scan ID, Scanner, Policy ID
        total = 0

        # Cycle through each asset record
        for assets in scan[1].values():
            # Gather a total
            total = assets + total

        # After calculating the total, lets get an average
        average = total/length

        average_dict[scan[0]] = [int(average), length]
    return average_dict


def parse_19506_data():
    # Pull all 19506 Plugins from the DB
    plugin_data = db_query("select asset_uuid, output from vulns where plugin_id='19506';")

    # Set some dicts for organizing Data
    scan_policy_dict = {}
    scanner_dict = {}
    scan_name_dict = {}

    # Loop through each plugin 19506 and Parse data from it
    for vulns in plugin_data:

        # Output is the second item in the tuple from the DB
        plugin_output = vulns[1]

        # split the output by return
        parsed_output = plugin_output.split("\n")

        # grab the length so we can grab the seconds
        plugin_length = len(parsed_output)

        # grab the scan duration- second to the last variable
        duration = parsed_output[plugin_length - 2]

        # Split at the colon to grab the numerical value
        seconds = duration.split(" : ")

        # split to remove "secs"
        number = seconds[1].split(" ")

        # grab the number for our minute calculation
        final_number = number[0]

        if final_number != 'unknown':
            # convert seconds into minutes
            minutes = int(final_number) / 60

            # Grab data pair and split it at the colon and grab the values
            try:
                scan_name = parsed_output[9].split(" : ")[1]
                scan_policy = parsed_output[10].split(" : ")[1]
                scanner_ip = parsed_output[11].split(" : ")[1]

                # Organize Data by Scan Policy
                # If the category is not in the new dict, add it; else update it.
                if scan_policy not in scan_policy_dict:
                    scan_policy_dict[scan_policy] = {vulns[0]: minutes}
                else:
                    scan_policy_dict[scan_policy].update({vulns[0]: minutes})

                if scanner_ip not in scanner_dict:
                    scanner_dict[scanner_ip] = {vulns[0]: minutes}
                else:
                    scanner_dict[scanner_ip].update({vulns[0]: minutes})

                if scan_name not in scan_name_dict:
                    scan_name_dict[scan_name] = {vulns[0]: minutes}
                else:
                    scan_name_dict[scan_name].update({vulns[0]: minutes})
            except IndexError:
                print("You likely have old plugin sets. Skipping this plugin since the scan didn't finish.")
                pass

    return scan_policy_dict, scanner_dict, scan_name_dict


def readiness_check():
    try:
        vuln_check = db_query("select count(*) from vulns;")
        vuln_message = "You have {} plugins in the navi database".format(vuln_check[0][0])
        if vuln_check[0][0] == 0:
            vuln_color = "Red"
        else:
            vuln_color = "Green"
    except:
        vuln_message = "Update the navi with Vulns"
        vuln_color = "Red"

    try:
        asset_check = db_query("select count(*) from assets;")
        asset_message = "You have {} assets in the navi database".format(asset_check[0][0])
        if asset_check[0][0] == 0:
            asset_color = "Red"
        else:
            asset_color = "Green"
    except:
        asset_message = "Update navi with Assets"
        asset_color = "Red"

    try:
        fixed_check = db_query("select count(*) from fixed;")
        fixed_message = "Fixed Data Downloaded!".format(fixed_check)
        fixed_color = "Green"
    except:
        fixed_message = "Update navi with fixed vulns"
        fixed_color = "Red"

    try:
        sla_check = db_query("select count(*) from sla;")
        sla_message = "Your SLA is Set"
        sla_color = "Green"
    except:
        sla_message = "Set your SLA"
        sla_color = "Red"
    return vuln_color, asset_color, sla_color, fixed_color


def reset_sla(critical, high, medium, low):
    database = r"navi.db"
    conn = new_db_connection(database)
    drop_tables(conn, 'sla')

    create_sla_table = """CREATE TABLE IF NOT EXISTS sla (
                                critical text,
                                high text,
                                medium text, 
                                low text 
                                );"""
    create_table(conn, create_sla_table)

    sla_info = (critical, high, medium, low)
    with conn:
        sql = '''INSERT or IGNORE into sla(critical, high, medium, low) VALUES(?,?,?,?)'''
        cur = conn.cursor()
        cur.execute(sql, sla_info)


def create_add_magic_url(data):
    url_base = "https://cloud.tenable.com/tio/app.html#/findings/host-vulnerabilities?f="
    data_list = []
    for row in data:
        new_data = []
        asset_filter = {"id": "asset.id", "operator": "eq", "value": 0}

        plugin_filter = {"id": "definition.id", "operator": "eq", "value": 0}

        # filter params that follow the base64 querystring
        after_filter = "&s=&findings_host_vulnerabilities.st=severity.0"

        # change our asset UUID
        asset_filter["value"] = row[1]

        # Change the plugin ID
        plugin_filter["value"] = row[2]

        # Combine both Filters into a list
        pre_filter_list = [asset_filter, plugin_filter]

        # Turn the list into json
        filter_list = json.dumps(pre_filter_list)

        # Encode the json list into base64
        base64_filter = base64.b64encode(filter_list.encode('ascii'))

        # build the 3 part URL
        full_url = "{}{}{}".format(url_base, base64_filter.decode('UTF-8'), after_filter)

        # Break up the tuple and populate a new list
        for item in row:
            new_data.append(item)

        # Add the URL to the list
        new_data.append(full_url)

        # add the list too the master list
        data_list.append(new_data)

    return data_list


def scantime(minute):
    data = db_query("SELECT asset_ip, asset_uuid, plugin_id, plugin_name, score, output from vulns where plugin_id='19506';")

    scantime_list = []
    for vulns in data:

        plugin_output = vulns[5]

        # split the output by return
        parsed_output = plugin_output.split("\n")

        # grab the length so we can grab the seconds
        length = len(parsed_output)

        # grab the scan duration- second to the last variable
        duration = parsed_output[length - 2]

        # Split at the colon to grab the numerical value
        seconds = duration.split(" : ")

        # split to remove "secs"
        number = seconds[1].split(" ")

        # grab the number for our minute calculation
        final_number = number[0]

        if final_number != 'unknown':
            # convert seconds into minutes
            minutes = int(final_number) / 60

            # grab assets that match the criteria
            if minutes > int(minute):
                try:
                    scantime_list.append([str(vulns[0]), str(vulns[1]), str(vulns[2]), str(vulns[3]), str(vulns[4])])
                except ValueError:
                    pass
    return scantime_list


def run_rules_now():
    try:
        print("Running Rules")
        data = "\nRunning Tag Rules\n"

        rule_data = db_query("select * from rules;")
        for rule in rule_data:

            if rule[3] == 'plugin_id':
                message = "\nTag on plugin ID: {}\n".format(rule[4])
                data = data + message + str(subprocess.run(['navi', 'tag', '--c', rule[1], '--v', rule[2], '--plugin', rule[4]], capture_output=True, text=True).stdout)

            elif rule[3] == 'plugin_name':
                message = "\nTag on plugin name: {}\n".format(rule[4])
                data = data + message + str(subprocess.run(['navi', 'tag', '--c', rule[1], '--v', rule[2], '--name', rule[4]], capture_output=True, text=True).stdout)

            elif rule[3] == 'plugin_output':
                message = "\nTag on '{}' found in the output of plugin ID: {}\n".format(rule[4], rule[5])
                data = data + message + str(subprocess.run(['navi', 'tag', '--c', rule[1], '--v', rule[2], '--plugin', rule[5], '--output', rule[4]], capture_output=True, text=True).stdout)

            elif rule[3] == 'cve':
                message = "\nTag on cve ID: {}\n".format(rule[4])
                data = data + message + str(subprocess.run(['navi', 'tag', '--c', rule[1], '--v', rule[2], '--cve', rule[4]], capture_output=True, text=True).stdout)

            elif rule[3] == 'xref':
                if rule[5]:
                    message = "\nTag on '{}' found in the Cross References with '{}' found in the Reference ID\n".format(rule[5], rule[4])
                    data = data + message + str(subprocess.run(['navi', 'tag', '--c', rule[1], '--v', rule[2], '--xref', rule[5], '--xid', rule[4]], capture_output=True, text=True).stdout)
                else:
                    message = "\nTag on '{}' found in the Cross References\n".format(rule[4])
                    data = data + message + str(subprocess.run(['navi', 'tag', '--c', rule[1], '--v', rule[2], '--xref', rule[4]], capture_output=True, text=True).stdout)

            elif rule[3] == 'scanid':
                message = "\nTag on scan ID: {}\n".format(rule[4])
                data = data + message + str(subprocess.run(['navi', 'tag', '--c', rule[1], '--v', rule[2], '--scanid', rule[4]], capture_output=True, text=True).stdout)

            elif rule[3] == 'scantime':
                message = "\nTag assets that took longer than '{} mins' to scan\n".format(rule[4])
                data = data + message + str(subprocess.run(['navi', 'tag', '--c', rule[1], '--v', rule[2], '--scantime', rule[4]], capture_output=True, text=True).stdout)

            elif rule[3] == 'group':
                message = "\nTag on Agent Group: {}\n".format(rule[4])
                data = data + message + str(subprocess.run(['navi', 'tag', '--c', rule[1], '--v', rule[2], '--group', rule[4]], capture_output=True, text=True).stdout)
            else:
                message = "\nTag by port: {}\n".format(rule[4])
                data = data + message + str(subprocess.run(['navi', 'tag', '--c', rule[1], '--v', rule[2], '--port', rule[4]], capture_output=True, text=True).stdout)
            print(data)
        return data
    except:
        pass


@app.route('/tags', methods=["GET", "POST"])
def main():

    if request.method == "POST":
        create_rules_table()
        navi_uuid = uuid.uuid1()
        database = r"navi.db"
        tag_conn = new_db_connection(database)
        category = request.form["Category"]
        value = request.form["Value"]
        method = request.form["tag_method"]
        search_text = request.form["search_text"]
        try:
            plugin_id = request.form["plugin_id_output"]
        except:
            plugin_id = ""

        with tag_conn:
            tag_list = [str(navi_uuid), category, value, method, search_text, plugin_id, "Never", ""]
            insert_rules(tag_conn, tag_list)

        return redirect(url_for('main'))

    if request.method == "GET":
        create_rules_table()
        vuln, asset, sla, fixed = readiness_check()
        if sla == "Green":
            if vuln == "Green":
                tags = db_query("select * from rules;")

                return render_template("tagging.html", tags=tags)
        else:
            data = "Database Not Ready"
            bytes_data = bytes(data, 'utf-8')
            query_ans = base64.b64encode(bytes_data)
            return redirect(url_for('configure_navi', data=query_ans))


@app.route('/delete')
def delete():
    tag_uuid = request.args['remove']
    delete_request = db_query("delete from rules where uuid='{}';".format(str(tag_uuid)))
    return redirect(url_for('main'))


@app.route('/stats', methods=["GET"])
def get_scan_stats():
    vuln, asset, sla, fixed = readiness_check()
    if sla == "Green":
        if fixed == "Green":
            scan_policy_dict, scanner_dict, scan_name_dict = parse_19506_data()

            policy_average = average_by_policy(scan_policy_dict)

            scanner_average = average_by_policy(scanner_dict)

            scan_name_average = average_by_policy(scan_name_dict)

            return render_template("scan_stats.html", policy_average=policy_average, scanner_average=scanner_average, scan_name_average=scan_name_average)
    else:
        data = "Database Not Ready"
        bytes_data = bytes(data, 'utf-8')
        query_ans = base64.b64encode(bytes_data)
        return redirect(url_for('configure_navi', data=query_ans))


@app.route('/sla', methods=["GET"])
def get_sla():
    vuln, asset, sla, fixed = readiness_check()
    if sla == "Green":
        if vuln == "Green":
            totals_dict = {}
            sla_data = ''
            try:
                sla_data = db_query("select * from sla;")

                critical, high, medium, low = sla_data[0]
                sla_data = [critical, high, medium, low]
            except:
                # on failure, lets set the defaults.
                critical = 7
                high = 14
                medium = 30
                low = 180
                reset_sla(critical, high, medium, low)

            total = db_query("select count(plugin_id) from fixed where severity !='info';")[0][0]
            pass_total = db_query("select count(plugin_id) from fixed where state=='FIXED' and pass_fail =='Pass';")[0][0]
            fixed_total = db_query("select count(plugin_id) from fixed where state=='FIXED';")[0][0]

            try:
                fixed_rate = fixed_total/ total
            except ZeroDivisionError:
                fixed_rate = "0"

            try:
                success_rate = pass_total / total
            except ZeroDivisionError:
                success_rate = "0"

            for severity in ["critical", "high", "medium", "low"]:
                severity_total = db_query("select count(plugin_id) from fixed where severity =='{}';".format(severity))
                sevrity_pass_total = db_query(
                    "select count(plugin_id) from fixed where severity =='{}' and pass_fail =='Pass';".format(severity))[0][0]

                try:
                    success_rate_sev = float(sevrity_pass_total) / float(severity_total[0][0])
                except ZeroDivisionError:
                    success_rate_sev = "0"

                totals_dict[severity] = {"Total vulns": severity_total[0][0], "Fixed Total": sevrity_pass_total,
                                         "success rate": format(success_rate_sev, '.2f')}

            return render_template("sla_stats.html", total=total, pass_total=pass_total, fixed_rate=fixed_rate,
                                   success_rate_sev=success_rate_sev, success_rate=format(success_rate, '.2f'), totals_dict=totals_dict,
                                   sla_data=sla_data, sevrity_pass_total=sevrity_pass_total)
    else:
        data = "Database Not Ready"
        bytes_data = bytes(data, 'utf-8')
        query_ans = base64.b64encode(bytes_data)
        return redirect(url_for('configure_navi', data=query_ans))


@app.route('/', methods=["GET", "POST"])
def configure_navi():
    key_color = "Red"
    key_message = "No Keys or Incorrect Keys added"

    if request.method == "GET":
        # Send a requests to scans endpoint to verifiy api keys
        keys_check = request_data("GET", "/users")
        status = keys_check.status_code
        print(status)
        if status == 200:
            key_message = "Keys Activated!"
            key_color = "Green"

    data = ""
    query_string_data = request.args.get('data')
    if query_string_data:
        new_data = base64.b64decode(query_string_data)
        data = new_data.decode('UTF-8')

    try:

        vuln_check = db_query("select count(*) from vulns;")
        vuln_message = "You have {} plugins in the navi database".format(vuln_check[0][0])
        if vuln_check[0][0] == 0:
            vuln_color = "Red"
        else:
            vuln_color = "Green"
    except:
        vuln_message = "Update the navi with Vulns"
        vuln_color = "Red"

    try:
        asset_check = db_query("select count(*) from assets;")
        asset_message = "You have {} assets in the navi database".format(asset_check[0][0])
        if asset_check[0][0] == 0:
            asset_color = "Red"
        else:
            asset_color = "Green"
    except:
        asset_message = "Update navi with Assets"
        asset_color = "Red"

    try:
        fixed_check = db_query("select count(*) from fixed;")
        fixed_message = "Fixed Data Downloaded!".format(fixed_check)
        fixed_color = "Green"
    except:
        fixed_message = "Update navi with fixed vulns"
        fixed_color = "Red"

    try:
        sla_check = db_query("select count(*) from sla;")
        sla_message = "Your SLA is Set"
        sla_color = "Green"
    except:
        sla_message = "Set your SLA"
        sla_color = "Red"

    return render_template('index.html', key_color=key_color, vuln_color=vuln_color, asset_color=asset_color,
                           fixed_color=fixed_color, sla_color=sla_color, key_message=key_message, vuln_message=vuln_message,
                           asset_message=asset_message, sla_message=sla_message, fixed_message=fixed_message, data=data)


@app.route('/keys', methods=["POST"])
def config_keys():
    access_key = request.form["Access_key"]
    secret_key = request.form["Secret_key"]

    keys(access_key=access_key, secret_key=secret_key)

    return redirect(url_for('configure_navi'))


@app.route('/vulns', methods=["POST"])
def update_vuns():
    days = request.form["Days"]
    threads = request.form["Threads"]
    exid = request.form["Exid"]

    if exid != 'NONE':
        data = str(subprocess.run(['navi', 'update', 'vulns', '--days', str(days), '--threads', str(threads), '--exid', exid], capture_output=True, text=True).stdout)
    else:
        data = str(subprocess.run(['navi', 'update', 'vulns', '--days', str(days), '--threads', str(threads)], capture_output=True, text=True).stdout)

    bytes_data = bytes(data, 'utf-8')
    query_ans = base64.b64encode(bytes_data)
    return redirect(url_for('configure_navi', data=query_ans))


@app.route('/assets', methods=["POST"])
def update_assets():
    asset_days = request.form["asset_days"]
    asset_threads = request.form["asset_threads"]
    asset_exid = request.form["asset_exid"]

    if asset_exid != 'NONE':
        data = str(subprocess.run(['navi', 'update', 'assets', '--days', str(asset_days), '--threads', str(asset_threads), '--exid', asset_exid], capture_output=True, text=True).stdout)
    else:
        data = str(subprocess.run(['navi', 'update', 'assets', '--days', str(asset_days), '--threads', str(asset_threads)], capture_output=True, text=True).stdout)

    bytes_data = bytes(data, 'utf-8')
    query_ans = base64.b64encode(bytes_data)
    return redirect(url_for('configure_navi', data=query_ans))


@app.route('/fixed', methods=["POST"])
def update_fixed():
    fixed_days = request.form["fixed_days"]
    fixed_cat = request.form["fixed_cat"]
    fixed_val = request.form["fixed_val"]

    if fixed_cat == '(Optional) Tag Category':
        sys('navi update fixed --days {}'.format(fixed_days))
        data = "Job Complete"
    else:
        sys('navi update fixed --days {} --c {} --v {}'.format(fixed_days, fixed_cat, fixed_val))
        data = "Job Complete"
    bytes_data = bytes(data, 'utf-8')
    query_ans = base64.b64encode(bytes_data)
    return redirect(url_for("configure_navi", data=query_ans))


@app.route('/reset_sla', methods=["POST"])
def reset_sla():
    critical = request.form["critical"]
    high = request.form["high"]
    medium = request.form["medium"]
    low = request.form["low"]

    data = str(subprocess.run(['navi', 'sla', '--critical', str(critical), '--high', str(high), '--medium', str(medium), '--low', str(low), '-reset'], capture_output=True, text=True).stdout)
    bytes_data = bytes(data, 'utf-8')
    query_ans = base64.b64encode(bytes_data)
    return redirect(url_for('configure_navi', data=query_ans))


@app.route('/search')
def navi_search():
    vuln, asset, sla, fixed = readiness_check()
    if vuln == "Green" and asset == "Green":
        search_method = request.args.get("search_method")
        search_text = request.args.get("search_text")
        secondary_search = request.args.get("secondary_search")

        if search_method == "plugin_id":

            plugin_data = db_query("select asset_ip, asset_uuid, plugin_id, plugin_name, score from vulns where plugin_id ='{}';".format(search_text))
            new_list = create_add_magic_url(plugin_data)

            return render_template('navi_gate.html', new_list=new_list, title="Results for Plugin ID: '{}'".format(search_text))

        elif search_method == "output":
            if secondary_search:
                output_data = db_query("select asset_ip, asset_uuid, plugin_id, plugin_name, score from vulns where plugin_id ='{}' AND output LIKE '%{}%';".format(secondary_search, search_text))
                new_list = create_add_magic_url(output_data)

                return render_template('navi_gate.html', new_list=new_list, title="Results for Plugin ID: '{}' With '{}' found in the output".format(search_text, secondary_search))
            else:
                output_data = db_query("select asset_ip, asset_uuid, plugin_id, plugin_name, score from vulns where output LIKE '%{}%';".format(search_text))
                new_list = create_add_magic_url(output_data)

                return render_template('navi_gate.html', new_list=new_list, title="Results with '{}' found in the output".format(search_text))

        elif search_method == "ports":
            ports_data = db_query("select asset_ip, asset_uuid, plugin_id, plugin_name, score from vulns where port='{}';".format(search_text))
            new_list = create_add_magic_url(ports_data)

            return render_template('navi_gate.html', new_list=new_list, title="Results for Port: '{}' found Open".format(search_text))

        elif search_method == "cve":
            cve_data = db_query("select asset_ip, asset_uuid, plugin_id, plugin_name, score from vulns where cves LIKE '%{}%';".format(search_text))
            new_list = create_add_magic_url(cve_data)

            return render_template('navi_gate.html', new_list=new_list, title="Results for CVE-ID: '{}'".format(search_text))

        elif search_method == "xref":
            if secondary_search:
                xref_data = db_query("select asset_ip, asset_uuid, plugin_id, plugin_name, score from vulns where xrefs LIKE '%{}%' AND xrefs LIKE '%{}%';".format(search_text, secondary_search))
                new_list = create_add_magic_url(xref_data)

                return render_template('navi_gate.html', new_list=new_list, title="Cross References\n'{}':'{}'".format(search_text, secondary_search))
            else:
                xref_data = db_query("select asset_ip, asset_uuid, plugin_id, plugin_name, score from vulns where xrefs LIKE '%{}%';".format(search_text))
                new_list = create_add_magic_url(xref_data)

                return render_template('navi_gate.html', new_list=new_list, title="Results for xref: '{}'".format(search_text))

        elif search_method == "plugin_name":
            name_data = db_query("select asset_ip, asset_uuid, plugin_id, plugin_name, score from vulns where plugin_name LIKE '%{}%';".format(search_text))
            new_list = create_add_magic_url(name_data)

            return render_template('navi_gate.html', new_list=new_list, title="Results for plugins where: '{}' was found in the Plugin Name".format(search_text))

        elif search_method == "scantime":
            scantime_list = scantime(search_text)
            new_list = create_add_magic_url(scantime_list)

            return render_template('navi_gate.html', new_list=new_list, title="Results for Assets taking longer than: '{}' mins to scan".format(search_text))

        else:
            return render_template('navi_gate.html', title="Search the Navi Database")
    else:
        data = "Database Not Ready"
        bytes_data = bytes(data, 'utf-8')
        query_ans = base64.b64encode(bytes_data)
        return redirect(url_for('configure_navi', data=query_ans))


@app.route('/runrules')
def runrules():
    # Todo: This logic will get be a problem for scanners Needs to take some kind of input
    data = run_rules_now()
    time_now = datetime.datetime.fromtimestamp(int(time.time())).strftime('%m-%d %H:%M')

    def create_magic_url(uuid):

        # craft url for specific uuid
        url_base = 'https://cloud.tenable.com/tio/app.html#/assets-uw/all-assets/list?s=&uw_all_assets_list.st=last_observed.1&f='
        pre_tag_filter = [{"id": "tags", "operator": "eq", "value": ["{}".format(uuid)]}]

        # Turn the list into json
        filter_list = json.dumps(pre_tag_filter)

        # Encode the json list into base64
        base64_filter = base64.b64encode(filter_list.encode('ascii'))

        # build the 3 part URL
        full_url = "{}{}".format(url_base, base64_filter.decode('UTF-8'))

        return full_url

    for tag in tio.tags.list():
        tag_uuid = tag['uuid']
        tag_cat = tag['category_name']
        tag_val = tag['value']
        magic_url = create_magic_url(tag_uuid)
        update_date = db_query("UPDATE rules SET uuid = '{}', run_date='{}', magic_url = '{}' where category = '{}' AND value = '{}';".format(tag_uuid,time_now, magic_url, tag_cat, tag_val))

    return render_template("results.html", data=data, title="Tenable Tags")


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
