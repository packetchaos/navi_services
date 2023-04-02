from api_wrapper import tenb_connection, request_data
from database import db_query
import time
import json
import base64

tio = tenb_connection()
time_now = time.time()


def create_tag_magic_url(uuid):
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
    magic_url = create_tag_magic_url(tag_uuid)
    data = db_query("UPDATE rules SET uuid = '{}', run_date='{}', magic_url = '{}' where category = '{}' AND value = '{}';".format(tag_uuid,time_now, magic_url, tag_cat, tag_val))

data = db_query("select * from rules;")

print(data)
