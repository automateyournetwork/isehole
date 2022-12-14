import os
import json
import requests
import aiohttp
import asyncio
import aiofiles
import rich_click as click
import yaml
import urllib3
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

urllib3.disable_warnings()

class ISEHole():
    def __init__(self,
                url,
                username,
                password):
        self.ise = url
        self.username = username
        self.password = password
        self.nohttpurl = url.replace("https://","")

    def isehole(self):
        self.make_directories()
        asyncio.run(self.main())

    def make_directories(self):
        folder_list = ["Active Directory",
                       "Admin Users",
                       "Allowed Protocols",
                       "Authentication Dictionary",
                       "Authentication Policy Sets",
                       "Authorization Dictionary",
                       "Authorization Policy Sets",
                       "Authorization Profile",
                       "Command Set",
                       "Conditions",
                       "CSR",
                       "DACL",
                       "Deployment Info",
                       "Deployment Nodes",
                       "Endpoint Groups",
                       "Endpoints",
                       "Eval Licenses",
                       "Hot Patches",
                       "Identity Groups",
                       "Identity Store Sequences",
                       "Identity Stores",
                       "Internal Users",
                       "Last Backup",
                       "License Connection Type",
                       "License Feature Map",
                       "License Register",
                       "License Smart State",
                       "License Tier State",
                       "NBAR Apps",
                       "Network Access Condition Authentication",
                       "Network Access Condition Authorization",
                       "Network Access Condition Policy Sets",
                       "Network Access Conditions",
                       "Network Access Dictionary Authentication",
                       "Network Access Dictionary Authorization",
                       "Network Access Dictionary Policy Sets",
                       "Network Access Dictionaries",
                       "Network Access Identity Stores",
                       "Network Access Policy Authentication",
                       "Network Access Policy Authorization",
                       "Network Access Policy Sets",
                       "Network Access Security Groups",
                       "Network Access Service Names",
                       "Network Authorization Profiles",
                       "Network Device Groups",
                       "Network Devices",
                       "Node Interfaces",
                       "Node Profiles",
                       "Nodes",
                       "PAN HA",
                       "Patch",
                       "Policy Set Dictionary",
                       "Policy Sets",
                       "Portals",
                       "Profilers",
                       "Proxies",
                       "Repositories",
                       "Self Registration Portal",
                       "Service Names",
                       "SGT ACLs",
                       "SGTs",
                       "Shell Profiles",
                       "Sponsor Groups",
                       "Sponsored Guest Portals",
                       "Sponsor Portals",
                       "System Certificates",
                       "Transport Gateways",
                       "Trusted Certificates",
        ]
        current_directory = os.getcwd()
        for folder in folder_list:
            final_directory = os.path.join(current_directory, rf'{ folder }/JSON')
            os.makedirs(final_directory, exist_ok=True)
            final_directory = os.path.join(current_directory, rf'{ folder }/YAML')
            os.makedirs(final_directory, exist_ok=True)
            final_directory = os.path.join(current_directory, rf'{ folder }/CSV')
            os.makedirs(final_directory, exist_ok=True)
            final_directory = os.path.join(current_directory, rf'{ folder }/HTML')
            os.makedirs(final_directory, exist_ok=True)
            final_directory = os.path.join(current_directory, rf'{ folder }/Markdown')
            os.makedirs(final_directory, exist_ok=True)
            final_directory = os.path.join(current_directory, rf'{ folder }/Mindmap')
            os.makedirs(final_directory, exist_ok=True)

    def api_list(self):
        self.api_list = ["/ers/config/allowedprotocols",
                    "/ers/config/adminuser",
                    "/ers/config/activedirectory",
                    "/ers/config/authorizationprofile",
                    "/ers/config/downloadableacl",
                    "/ers/config/endpoint",
                    "/ers/config/endpointgroup",
                    "/ers/config/identitygroup",
                    "/ers/config/idstoresequence",
                    "/ers/config/internaluser",
                    "/ers/config/networkdevice",
                    "/ers/config/networkdevicegroup",
                    "/ers/config/node",
                    "/ers/config/portal",
                    "/ers/config/profilerprofile",
                    "/ers/config/deploymentinfo/getAllInfo",
                    "/ers/config/sgt",
                    "/ers/config/sgacl",
                    "/ers/config/selfregportal",
                    "/ers/config/sponsorgroup",
                    "/ers/config/sponsorportal",
                    "/ers/config/sponsoredguestportal",
                    "/api/v1/backup-restore/config/last-backup-status",
                    "/api/v1/certs/certificate-signing-request",
                    f"/api/v1/certs/system-certificate/{ self.nohttpurl }",
                    "/api/v1/certs/trusted-certificate",
                    "/api/v1/deployment/node",
                    "/api/v1/deployment/pan-ha",
                    f"/api/v1/node/{ self.nohttpurl }/interface",
                    f"/api/v1/profile/{ self.nohttpurl }",
                    "/api/v1/license/system/connection-type",
                    "/api/v1/license/system/eval-license",
                    "/api/v1/license/system/feature-to-tier-mapping",
                    "/api/v1/license/system/register",
                    "/api/v1/license/system/smart-state",
                    "/api/v1/license/system/tier-state",
                    "/api/v1/patch",
                    "/api/v1/hotpatch",
                    "/api/v1/repository",
                    "/api/v1/system-settings/proxy",
                    "/api/v1/system-settings/telemetry/transport-gateway",
                    "/api/v1/trustsec/sgacl/nbarapp/",
                    "/api/v1/policy/device-admin/command-sets",
                    "/api/v1/policy/device-admin/condition",
                    "/api/v1/policy/device-admin/dictionaries/authentication",
                    "/api/v1/policy/device-admin/dictionaries/authorization",
                    "/api/v1/policy/device-admin/dictionaries/policyset",
                    "/api/v1/policy/device-admin/identity-stores",
                    "/api/v1/policy/device-admin/policy-set",
                    "/api/v1/policy/device-admin/service-names",
                    "/api/v1/policy/device-admin/shell-profiles",
                    "/api/v1/policy/network-access/authorization-profiles",
                    "/api/v1/policy/network-access/condition",
                    "/api/v1/policy/network-access/condition/authentication",
                    "/api/v1/policy/network-access/condition/authorization",
                    "/api/v1/policy/network-access/condition/policyset",
                    "/api/v1/policy/network-access/dictionaries",
                    "/api/v1/policy/network-access/dictionaries/authentication",
                    "/api/v1/policy/network-access/dictionaries/authorization",
                    "/api/v1/policy/network-access/dictionaries/policyset",
                    "/api/v1/policy/network-access/identity-stores",
                    "/api/v1/policy/network-access/policy-set",
                    "/api/v1/policy/network-access/security-groups",
                    "/api/v1/policy/network-access/service-names",
        ]

    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
    }
    async def get_api(self, api_url):
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{self.ise}{api_url}",cookies = self.cookie, verify_ssl=False) as resp:
                response_dict = await resp.json()
                print(f"{api_url} Status Code {resp.status}")
                return (api_url,response_dict)

    async def main(self):
        results = await asyncio.gather(*(self.get_api(api_url) for api_url in self.api_list))
        await self.all_files(json.dumps(results, indent=4, sort_keys=True))

    async def json_file(self, parsed_json):
        for api, payload in json.loads(parsed_json):
            if "/ers/config/allowedprotocols" in api:
                async with aiofiles.open('Allowed Protocols/JSON/Allowed Protocols.json', mode='w') as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

    async def yaml_file(self, parsed_json):
        for api, payload in json.loads(parsed_json):
            clean_yaml = yaml.dump(payload, default_flow_style=False)
            if "/ers/config/allowedprotocols" in api:
                async with aiofiles.open('Allowed Protocols/YAML/Allowed Protocols.yaml', mode='w' ) as f:
                    await f.write(clean_yaml)

    # async def csv_file(self, parsed_json):
    #     template_dir = Path(__file__).resolve().parent
    #     env = Environment(loader=FileSystemLoader(str(template_dir)), enable_async=True)
    #     csv_template = env.get_template('ise_csv.j2')
    #     for api, payload in json.loads(parsed_json):        
    #         csv_output = await csv_template.render_async(api = api,
    #                                      data_to_template = payload)
    #         if "Tenant" in api:
    #             async with aiofiles.open('Tenant/CSV/Tenants.csv', mode='w' ) as f:
    #                 await f.write(csv_output)

    # async def markdown_file(self, parsed_json):
    #     template_dir = Path(__file__).resolve().parent
    #     env = Environment(loader=FileSystemLoader(str(template_dir)), enable_async=True)
    #     markdown_template = env.get_template('ise_markdown.j2')
    #     for api, payload in json.loads(parsed_json):        
    #         markdown_output = await markdown_template.render_async(api = api,
    #                                      data_to_template = payload)
    #         if "Tenant" in api:
    #             async with aiofiles.open('Tenant/CSV/Tenants.md', mode='w' ) as f:
    #                 await f.write(markdown_output)

    # async def html_file(self, parsed_json):
    #     template_dir = Path(__file__).resolve().parent
    #     env = Environment(loader=FileSystemLoader(str(template_dir)), enable_async=True)
    #     html_template = env.get_template('ise_html.j2')
    #     for api, payload in json.loads(parsed_json):
    #         html_output = await html_template.render_async(api = api,
    #                                          data_to_template = payload)
    #         if "Tenant" in api:
    #             async with aiofiles.open('Tenant/HTML/Tenants.html', mode='w' ) as f:
    #                 await f.write(html_output)

    # async def mindmap_file(self, parsed_json):
    #     template_dir = Path(__file__).resolve().parent
    #     env = Environment(loader=FileSystemLoader(str(template_dir)), enable_async=True)
    #     mindmap_template = env.get_template('ise_mindmap.j2')
    #     for api, payload in json.loads(parsed_json):
    #         mindmap_output = await mindmap_template.render_async(api = api,
    #                                          data_to_template = payload)
    #         if "Tenant" in api:
    #             async with aiofiles.open('Tenant/Mindmap/Tenants.md', mode='w' ) as f:
    #                 await f.write(mindmap_output)

    async def all_files(self, parsed_json):
        await asyncio.gather(self.json_file(parsed_json))
        #self.yaml_file(parsed_json), self.csv_file(parsed_json), self.markdown_file(parsed_json), self.html_file(parsed_json), self.mindmap_file(parsed_json))

@click.command()
@click.option('--url',
    prompt="ISE URL",
    help="ISE URL",
    required=True,envvar="URL")
@click.option('--username',
    prompt="ISE Username",
    help="ISE Username",
    required=True,envvar="USERNAME")
@click.option('--password',
    prompt="ISE Password",
    help="ISE Password",
    required=True, hide_input=True,envvar="PASSWORD")
def cli(url,username,password):
    invoke_class = ISEHole(url,username,password)
    invoke_class.isehole()

if __name__ == "__main__":
    cli()
