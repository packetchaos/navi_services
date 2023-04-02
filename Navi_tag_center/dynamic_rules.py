from os import system as sys
from database import db_query


def run_rules_now():
    rule_data = db_query("select * from rules;")

    for rule in rule_data:
        if rule[3] == 'plugin_id':
            print("navi tag --c \"{}\" --v \"{}\" --plugin {}".format(rule[1], rule[2], rule[4]))
            sys("navi tag --c \"{}\" --v \"{}\" --plugin {}".format(rule[1], rule[2], rule[4]))

        elif rule[3] == 'plugin_name':
            print("navi tag --c \"{}\" --v \"{}\" --name \"{}\"".format(rule[1], rule[2], rule[4]))
            sys("navi tag --c \"{}\" --v \"{}\" --name \"{}\"".format(rule[1], rule[2], rule[4]))

        elif rule[3] == 'plugin_output':
            # Do later: Condition might be to look at all plugins or a specfic one
            print("navi tag --c \"{}\" --v \"{}\" --plugin {} --output {}".format(rule[1], rule[2], rule[5], rule[4]))
            sys("navi tag --c \"{}\" --v \"{}\" --plugin {} --output \"{}\"".format(rule[1], rule[2], rule[5], rule[4]))

        elif rule[3] == 'cve':
            print("navi tag --c \"{}\" --v \"{}\" --cve {}".format(rule[1], rule[2], rule[4]))
            sys("navi tag --c \"{}\" --v \"{}\" --cve \"{}\"".format(rule[1], rule[2], rule[4]))

        elif rule[3] == 'xref':

            if rule[5] != "":
                print("navi tag --c \"{}\" --v \"{}\" --xref {} --xid {}".format(rule[1], rule[2], rule[4], rule[5]))
                sys("navi tag --c \"{}\" --v \"{}\" --xref \"{}\" --xid \"{}\"".format(rule[1], rule[2], rule[4], rule[5]))

            else:
                print("navi tag --c \"{}\" --v \"{}\" --xref {}".format(rule[1], rule[2], rule[4]))
                sys("navi tag --c \"{}\" --v \"{}\" --xref \"{}\"".format(rule[1], rule[2], rule[4]))

        elif rule[3] == 'group':
            print("navi tag --c \"{}\" --v \"{}\" --group {}".format(rule[1], rule[2], rule[4]))
            sys("navi tag --c \"{}\" --v \"{}\" --group \"{}\"".format(rule[1], rule[2], rule[4]))

        elif rule[3] == 'scantime':
            print("navi tag --c \"{}\" --v \"{}\" --scantime {}".format(rule[1], rule[2], rule[4]))
            sys("navi tag --c \"{}\" --v \"{}\" --scantime \"{}\"".format(rule[1], rule[2], rule[4]))

        elif rule[3] == 'scanid':
            print("navi tag --c \"{}\" --v \"{}\" --scanid {}".format(rule[1], rule[2], rule[4]))
            sys("navi tag --c \"{}\" --v \"{}\" --scanid \"{}\"".format(rule[1], rule[2], rule[4]))

        elif rule[3] == 'ports':
            print("navi tag --c \"{}\" --v \"{}\" --port {}".format(rule[1], rule[2], rule[4]))
            sys("navi tag --c \"{}\" --v \"{}\" --port \"{}\"cd".format(rule[1], rule[2], rule[4]))

        else:
            print("{} not currently supported".format(rule[3]))
