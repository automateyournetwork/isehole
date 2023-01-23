import asyncio
import json
import os
from pathlib import Path
from typing import OrderedDict

import aiofiles
import aiohttp
import rich_click as click
import urllib3
import xmltodict
import yaml
from jinja2 import Environment, FileSystemLoader
from throttler import Throttler

urllib3.disable_warnings()


class ISEHole:
    def __init__(self, url, username, password) -> None:
        self.ise_url: str = url
        self.username: str = username
        self.password: str = password
        self.throttler: Throttler = Throttler(25)
        self.no_https_url: str = url.replace("https://", "")
        self.api_count: int = 0
        self.first_response_dict: dict
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def isehole(self) -> None:
        self.make_directories()
        asyncio.run(self.main())

    def make_directories(self) -> None:
        folder_list = [
            "Active Directory",
            "Active Sessions",
            "Admin Users",
            "Allowed Protocols",
            "Authentication Dictionaries",
            "Authorization Dictionaries",
            "Authorization Profiles",
            "Command Sets",
            "Conditions",
            "CSRs",
            "DACLs",
            "Deployment Nodes",
            "Endpoint Groups",
            "Endpoints",
            "Eval Licenses",
            "Failure Reasons",
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
            "Patches",
            "Policy Set Dictionary",
            "Policy Sets",
            "Portals",
            "Posture Count",
            "Profiler Count",
            "Profilers",
            "Proxies",
            "Repositories",
            "Self Registration Portals",
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
            "Version",
        ]

        subfolders = ["JSON", "YAML", "CSV", "HTML", "Markdown", "Mindmap"]
        current_directory = os.getcwd()
        for folder in folder_list:
            for subfolder in subfolders:
                final_directory = os.path.join(
                    current_directory, f"{folder}/{subfolder}"
                )
                os.makedirs(final_directory, exist_ok=True)

    def ise_api_list(self) -> list[str]:
        return [
            "/ers/config/endpoint?size=100",
            "/ers/config/identitygroup?size=100",
            "/ers/config/idstoresequence?size=100",
            "/ers/config/profilerprofile?size=100",
            "/ers/config/internaluser?size=100",
            "/ers/config/allowedprotocols?size=100",
            "/ers/config/adminuser?size=100",
            "/ers/config/activedirectory?size=100",
            "/ers/config/authorizationprofile?size=100",
            "/ers/config/downloadableacl?size=100",
            "/ers/config/endpointgroup?size=100",
            "/ers/config/networkdevice?size=100",
            "/ers/config/networkdevicegroup?size=100",
            "/ers/config/node?size=100",
            "/ers/config/portal?size=100",
            "/ers/config/sgt?size=100",
            "/ers/config/sgacl?size=100",
            "/ers/config/selfregportal?size=100",
            "/ers/config/sponsorgroup?size=100",
            "/ers/config/sponsorportal?size=100",
            "/ers/config/sponsoredguestportal?size=100",
            "/api/v1/backup-restore/config/last-backup-status",
            "/api/v1/certs/certificate-signing-request",
            f"/api/v1/certs/system-certificate/{self.no_https_url}",
            "/api/v1/certs/trusted-certificate",
            "/api/v1/deployment/node",
            "/api/v1/deployment/pan-ha",
            f"/api/v1/node/{self.no_https_url}/interface",
            f"/api/v1/profile/{self.no_https_url}",
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
            "/admin/API/mnt/Session/ActiveCount",
            "/admin/API/mnt/Session/PostureCount",
            "/admin/API/mnt/Session/ProfilerCount",
            "/admin/API/mnt/Version",
            "/admin/API/mnt/FailureReasons",
        ]

    async def get_next_pages(self, response_dict) -> list:
        async with aiohttp.ClientSession() as session:
            all_page_results = []
            all_page_results.append(self.first_response_dict)
            while "nextPage" in json.dumps(response_dict):
                next_page = response_dict["SearchResult"]["nextPage"]["href"]
                async with session.get(
                    f"{next_page}",
                    headers=self.headers,
                    auth=aiohttp.BasicAuth(self.username, self.password),
                    verify_ssl=False,
                ) as resp:
                    self.api_count += 1
                    response_dict = await resp.json()
                    all_page_results.append(response_dict)
                    print(next_page)
            return all_page_results

    async def get_ers_api_details(self, api_url) -> list:
        async with aiohttp.ClientSession(trust_env=True) as session:
            details_list = []
            async with self.throttler, session.get(
                f"{api_url['link']['href']}",
                headers=self.headers,
                auth=aiohttp.BasicAuth(self.username, self.password),
                verify_ssl=False,
            ) as resp:
                self.api_count += 1
                response_dict = await resp.json()
                print(api_url["link"]["href"])
                details_list.append(response_dict)
            return details_list

    async def get_open_api_details(self, api_url) -> list:
        async with aiohttp.ClientSession() as session:
            details_list = []
            async with session.get(
                f"{api_url['link']['href']}",
                headers=self.headers,
                auth=aiohttp.BasicAuth(self.username, self.password),
                verify_ssl=False,
            ) as resp:
                self.api_count += 1
                response_dict = await resp.json()
                print(api_url["link"]["href"])
                details_list.append(response_dict)
            return details_list

    async def get_api(
        self, api_url: str
    ) -> tuple[str, OrderedDict[str, list]] | tuple[str, list | str]:
        async with aiohttp.ClientSession() as session:
            if "mnt" in api_url:
                async with session.get(
                    f"{self.ise_url}{api_url}",
                    auth=aiohttp.BasicAuth(self.username, self.password),
                    verify_ssl=False,
                ) as resp:
                    self.api_count += 1
                    self.first_response_dict = await resp.text()
                    response_list = xmltodict.parse(self.first_response_dict)
                    return (api_url, response_list)

            async with session.get(
                f"{self.ise_url}{api_url}",
                headers=self.headers,
                auth=aiohttp.BasicAuth(self.username, self.password),
                verify_ssl=False,
            ) as resp:
                self.api_count += 1
                response_list = []
                self.first_response_dict = await resp.json()
                if "SearchResult" in json.dumps(self.first_response_dict):
                    if "nextPage" in json.dumps(self.first_response_dict):
                        response_dict = await asyncio.gather(
                            self.get_next_pages(self.first_response_dict)
                        )
                        response_list.append(response_dict)
                        response_list = response_list[0][0]
                    else:
                        response_list.append(self.first_response_dict)
                    detail_dict = await asyncio.gather(
                        *(
                            self.get_ers_api_details(api_url)
                            for result in response_list
                            for api_url in result["SearchResult"]["resources"]
                        )
                    )
                    response_list = detail_dict
                else:
                    response_list.append(self.first_response_dict)
                    if "href" in json.dumps(self.first_response_dict):
                        detail_dict = await asyncio.gather(
                            *(
                                self.get_open_api_details(api_url)
                                for result in response_list
                                for api_url in result["response"]
                            )
                        )
                        response_list = detail_dict
                    response_list = response_list[0]
                print(f"{api_url} Status Code {resp.status}")
                return (api_url, response_list)

    async def main(self) -> None:
        results = await asyncio.gather(
            *(self.get_api(api_url) for api_url in self.ise_api_list())
        )
        await self.all_files(json.dumps(results, indent=4, sort_keys=True))
        print(
            f"ISEHole gathered data from { self.api_count } Cisco Identity Services APIs"
        )

    async def write_file(self, file_format, api, payload):
        file_path_map = {
            "/ers/config/allowedprotocols": "Allowed Protocols/{file_format}/Allowed Protocols.{file_ext}",
            "/ers/config/adminuser": "Admin Users/{file_format}/Admin Users.{file_ext}",
            "/ers/config/activedirectory": "Active Directory/{file_format}/Active Directory.{file_ext}",
            "/ers/config/authorizationprofile": "Authorization Profiles/{file_format}/Authorization Profiles.{file_ext}",
            "/ers/config/downloadableacl": "DACLs/{file_format}/DACLs.{file_ext}",
            "/ers/config/endpoint": "Endpoints/{file_format}/Endpoints.{file_ext}",
            "/ers/config/endpointgr,up": "Endpoint Groups/{file_format}/Endpoint Groups.{file_ext}",
            "/ers/config/identitygroup": "Identity Groups/{file_format}/Identity Groups.{file_ext}",
            "/ers/config/idstoresequence": "Identity Store Sequences/{file_format}/Identity Store Sequences.{file_ext}",
            "/ers/config/internaluser": "Internal Users/{file_format}/Internal Users.{file_ext}",
            "/ers/config/networkdevice": "Network Devices/{file_format}/Network Devices.{file_ext}",
            "/ers/config/networkdevicegr,up": "Network Device Groups/{file_format}/Network Device Groups.{file_ext}",
            "/ers/config/node": "Nodes/{file_format}/Nodes.{file_ext}",
            "/ers/config/portal": "Portals/{file_format}/Portals.{file_ext}",
            "/ers/config/profilerprofile": "Profilers/{file_format}/Profilers.{file_ext}",
            "/ers/config/sgt": "SGTs/{file_format}/SGTs.{file_ext}",
            "/ers/config/sgacl": "SGT ACLs/{file_format}/SGT ACLs.{file_ext}",
            "/ers/config/selfregportal": "Self Registration Portals/{file_format}/Self Registration Portals.{file_ext}",
            "/ers/config/sponsorgroup": "Sponsor Groups/{file_format}/Sponsor Groups.{file_ext}",
            "/ers/config/sponsorportal": "Sponsor Portals/{file_format}/Sponsor Portals.{file_ext}",
            "/ers/config/sponsoredguestportal": "Sponsored Guest Portals/{file_format}/Sponsored Guest Portals.{file_ext}",
            "/api/v1/backup-restore/config/last-backup-status": "Last Backup/{file_format}/Last Backup.{file_ext}",
            "/api/v1/certs/certificate-signing-request": "CSRs/{file_format}/CSRs.{file_ext}",
            "/api/v1/certs/system-certificate": "System Certificates/{file_format}/System Certificates.{file_ext}",
            "/api/v1/certs/trusted-certificate": "Trusted Certificates/{file_format}/Trusted Certificates.{file_ext}",
            "/api/v1/deployment/node": "Deployment Nodes/{file_format}/Deployment Nodes.{file_ext}",
            "/api/v1/deployment/pan-ha": "PAN HA/{file_format}/PAN HA.{file_ext}",
            f"/api/v1/node/{ self.no_https_url }/interface": "Node Interfaces/{file_format}/Node Interfaces.{file_ext}",
            f"/api/v1/profile/{ self.no_https_url }": "Node Profiles/{file_format}/Node Profiles.{file_ext}",
            "/api/v1/license/system/connection-type": "License Connection Type/{file_format}/License Connection Type.{file_ext}",
            "/api/v1/license/system/eval-license": "Eval Licenses/{file_format}/Eval Licenses.{file_ext}",
            "/api/v1/license/system/feature-to-tier-mapping": "License Feature Map/{file_format}/License Feature Map.{file_ext}",
            "/api/v1/license/system/register": "License Register/{file_format}/License Register.{file_ext}",
            "/api/v1/license/system/smart-state": "License Smart State/{file_format}/License Smart State.{file_ext}",
            "/api/v1/license/system/tier-state": "License Tier State/{file_format}/License Tier State.{file_ext}",
            "/api/v1/patch": "Patches/{file_format}/Patches.{file_ext}",
            "/api/v1/hotpatch": "Hot Patches/{file_format}/Hot Patches.{file_ext}",
            "/api/v1/repository": "Repositories/{file_format}/Repositories.{file_ext}",
            "/api/v1/system-settings/proxy": "Proxies/{file_format}/Proxies.{file_ext}",
            "/api/v1/system-settings/telemetry/transport-gateway": "Transport Gateways/{file_format}/Transport Gateways.{file_ext}",
            "/api/v1/trustsec/sgacl/nbarapp/": "NBAR Apps/{file_format}/NBAR Apps.{file_ext}",
            "/api/v1/policy/device-admin/command-sets": "Command Sets/{file_format}/Command Sets.{file_ext}",
            "/api/v1/policy/device-admin/condition": "Conditions/{file_format}/Conditions.{file_ext}",
            "/api/v1/policy/device-admin/dictionaries/authentication": "Authentication Dictionaries/{file_format}/Authentication Dictionaries.{file_ext}",
            "/api/v1/policy/device-admin/dictionaries/authorization": "Authorization Dictionaries/{file_format}/Authorization Dictionaries.{file_ext}",
            "/api/v1/policy/device-admin/dictionaries/policyset": "Policy Set Dictionary/{file_format}/Policy Set Dictionary.{file_ext}",
            "/api/v1/policy/device-admin/identity-stores": "Identity Stores/{file_format}/Identity Stores.{file_ext}",
            "/api/v1/policy/device-admin/policy-set": "Policy Sets/{file_format}/Policy Sets.{file_ext}",
            "/api/v1/policy/device-admin/service-names": "Service Names/{file_format}/Service Names.{file_ext}",
            "/api/v1/policy/device-admin/shell-profiles": "Shell Profiles/{file_format}/Shell Profiles.{file_ext}",
            "/api/v1/policy/network-access/authorization-profiles": "Network Authorization Profiles/{file_format}/Network Authorization Profiles.{file_ext}",
            "/api/v1/policy/network-access/condition/authentication": "Network Access Condition Authentication/{file_format}/Network Access Condition Authentication.{file_ext}",
            "/api/v1/policy/network-access/condition/authorization": "Network Access Condition Authorization/{file_format}/Network Access Condition Authorization.{file_ext}",
            "/api/v1/policy/network-access/condition/policyset": "Network Access Condition Policy Sets/{file_format}/Network Access Condition Policy Sets.{file_ext}",
            "/api/v1/policy/network-access/condition": "Network Access Conditions/{file_format}/Network Access Conditions.{file_ext}",
            "/api/v1/policy/network-access/dictionaries": "Network Access Dictionaries/{file_format}/Network Access Dictionaries.{file_ext}",
            "/api/v1/policy/network-access/dictionaries/authentication": "Network Access Dictionary Authentication/{file_format}/Network Access Dictionary Authentication.{file_ext}",
            "/api/v1/policy/network-access/dictionaries/authorization": "Network Access Dictionary Authorization/{file_format}/Network Access Dictionary Authorization.{file_ext}",
            "/api/v1/policy/network-access/dictionaries/policyset": "Network Access Dictionary Policy Sets/{file_format}/Network Access Dictionary Policy Sets.{file_ext}",
            "/api/v1/policy/network-access/identity-stores": "Network Access Identity Stores/{file_format}/Network Access Identity Stores.{file_ext}",
            "/api/v1/policy/network-access/policy-set": "Network Access Policy Sets/{file_format}/Network Access Policy Sets.{file_ext}",
            "/api/v1/policy/network-access/security-groups": "Network Access Security Groups/{file_format}/Network Access Security Groups.{file_ext}",
            "/api/v1/policy/network-access/service-names": "Network Access Service Names/{file_format}/Network Access Service Names.{file_ext}",
            "/admin/API/mnt/Session/ActiveCount": "Active Sessions/{file_format}/Active Sessions.{file_ext}",
            "/admin/API/mnt/Session/PostureCount": "Posture Count/{file_format}/Posture Count.{file_ext}",
            "/admin/API/mnt/Session/ProfilerCount": "Profiler Count/{file_format}/Profiler Count.{file_ext}",
            "/admin/API/mnt/Version": "Version/{file_format}/Version.{file_ext}",
            "/admin/API/mnt/FailureReasons": "Failure Reasons/{file_format}/Failure Reasons.{file_ext}",
        }

        file_ext_map = {
            "yaml": "YAML",
            "json": "JSON",
            "csv": "CSV",
            "markdown": "Markdown",
            "html": "HTML",
            "mindmap": "Mindmap",
        }

        if file_format == "yaml":
            data = yaml.dump(data, default_flow_style=False)
        elif file_format == "json":
            data = json.dumps(data, indent=4, sort_keys=True)
        elif file_format == "csv":
            template_dir = Path(__file__).resolve().parent
            env = Environment(
                loader=FileSystemLoader(str(template_dir)), enable_async=True
            )
            csv_template = env.get_template("ise_csv.j2")
            data = await csv_template.render_async(data_to_template=data)
        elif file_format == "markdown":
            template_dir = Path(__file__).resolve().parent
            env = Environment(
                loader=FileSystemLoader(str(template_dir)), enable_async=True
            )
            markdown_template = env.get_template("ise_markdown.j2")
            data = await markdown_template.render_async(
                api=api, data_to_template=payload
            )
        elif file_format == "html":
            template_dir = Path(__file__).resolve().parent
            env = Environment(
                loader=FileSystemLoader(str(template_dir)), enable_async=True
            )
            html_template = env.get_template("ise_html.j2")
            data = await html_template.render_async(api=api, data_to_template=payload)
        elif file_format == "mindmap":
            template_dir = Path(__file__).resolve().parent
            env = Environment(
                loader=FileSystemLoader(str(template_dir)), enable_async=True
            )
            mindmap_template = env.get_template("ise_mindmap.j2")
            data = await mindmap_template.render_async(
                api=api, data_to_template=payload
            )
        else:
            raise ValueError("Invalid file format")

        file_path = file_path_map.get(api).format(
            file_format=file_format, file_ext=file_ext_map.get(file_format)
        )

        async with aiofiles.open(file_path, mode="w") as f:
            await f.write(data)

    async def yaml_file(self, parsed_json):
        for api, payload in json.loads(parsed_json):
            await self.write_file("yaml", api, payload)

    async def json_file(self, parsed_json):
        for api, payload in json.loads(parsed_json):
            await self.write_file("json", api, payload)

    async def csv_file(self, parsed_json):
        for api, payload in json.loads(parsed_json):
            await self.write_file("csv", api, payload)

    async def markdown_file(self, parsed_json):
        for api, payload in json.loads(parsed_json):
            await self.write_file("markdown", api, payload)

    async def html_file(self, parsed_json):
        for api, payload in json.loads(parsed_json):
            await self.write_file("html", api, payload)

    async def mindmap_file(self, parsed_json):
        for api, payload in json.loads(parsed_json):
            await self.write_file("mindmap", api, payload)

    async def all_files(self, parsed_json) -> None:
        await asyncio.gather(
            self.json_file(parsed_json),
            self.yaml_file(parsed_json),
            self.csv_file(parsed_json),
            self.markdown_file(parsed_json),
            self.html_file(parsed_json),
            self.mindmap_file(parsed_json),
        )


@click.command()
@click.option("--url", prompt="ISE URL", help="ISE URL", required=True, envvar="URL")
@click.option(
    "--username",
    prompt="ISE Username",
    help="ISE Username",
    required=True,
    envvar="USERNAME",
)
@click.option(
    "--password",
    prompt="ISE Password",
    help="ISE Password",
    required=True,
    hide_input=True,
    envvar="PASSWORD",
)
def cli(url, username, password):
    invoke_class = ISEHole(url, username, password)
    invoke_class.isehole()


if __name__ == "__main__":
    cli()
