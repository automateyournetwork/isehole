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

    async def json_file(self, parsed_json):
        for api, payload in json.loads(parsed_json):
            if "/ers/config/allowedprotocols" in api:
                async with aiofiles.open(
                    "Allowed Protocols/JSON/Allowed Protocols.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/ers/config/adminuser" in api:
                async with aiofiles.open(
                    "Admin Users/JSON/Admin Users.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/ers/config/activedirectory" in api:
                async with aiofiles.open(
                    "Active Directory/JSON/Active Directory.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/ers/config/authorizationprofile" in api:
                async with aiofiles.open(
                    "Authorization Profiles/JSON/Authorization Profiles.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/ers/config/downloadableacl" in api:
                async with aiofiles.open("DACLs/JSON/DACLs.json", mode="w") as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/ers/config/endpoint" in api:
                if "/ers/config/endpointgroup" in api:
                    async with aiofiles.open(
                        "Endpoint Groups/JSON/Endpoint Groups.json", mode="w"
                    ) as f:
                        await f.write(json.dumps(payload, indent=4, sort_keys=True))
                else:
                    async with aiofiles.open(
                        "Endpoints/JSON/Endpoints.json", mode="w"
                    ) as f:
                        await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/ers/config/identitygroup" in api:
                async with aiofiles.open(
                    "Identity Groups/JSON/Identity Groups.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/ers/config/idstoresequence" in api:
                async with aiofiles.open(
                    "Identity Store Sequences/JSON/Identity Store Sequences.json",
                    mode="w",
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/ers/config/internaluser" in api:
                async with aiofiles.open(
                    "Internal Users/JSON/Internal Users.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/ers/config/networkdevice" in api:
                if "/ers/config/networkdevicegroup" in api:
                    async with aiofiles.open(
                        "Network Device Groups/JSON/Network Device Groups.json",
                        mode="w",
                    ) as f:
                        await f.write(json.dumps(payload, indent=4, sort_keys=True))
                else:
                    async with aiofiles.open(
                        "Network Devices/JSON/Network Devices.json", mode="w"
                    ) as f:
                        await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/ers/config/node" in api:
                async with aiofiles.open("Nodes/JSON/Nodes.json", mode="w") as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/ers/config/portal" in api:
                async with aiofiles.open("Portals/JSON/Portals.json", mode="w") as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/ers/config/profilerprofile" in api:
                async with aiofiles.open(
                    "Profilers/JSON/Profilers.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/ers/config/sgt" in api:
                async with aiofiles.open("SGTs/JSON/SGTs.json", mode="w") as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/ers/config/sgacl" in api:
                async with aiofiles.open("SGT ACLs/JSON/SGT ACLs.json", mode="w") as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/ers/config/selfregportal" in api:
                async with aiofiles.open(
                    "Self Registration Portals/JSON/Self Registration Portals.json",
                    mode="w",
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/ers/config/sponsorgroup" in api:
                async with aiofiles.open(
                    "Sponsor Groups/JSON/Sponsor Groups.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/ers/config/sponsorportal" in api:
                async with aiofiles.open(
                    "Sponsor Portals/JSON/Sponsor Portals.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/ers/config/sponsoredguestportal" in api:
                async with aiofiles.open(
                    "Sponsored Guest Portals/JSON/Sponsored Guest Portals.json",
                    mode="w",
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/api/v1/backup-restore/config/last-backup-status" in api:
                async with aiofiles.open(
                    "Last Backup/JSON/Last Backup.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/api/v1/certs/certificate-signing-request" in api:
                async with aiofiles.open("CSRs/JSON/CSRs.json", mode="w") as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/api/v1/certs/system-certificate" in api:
                async with aiofiles.open(
                    "System Certificates/JSON/System Certificates.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/api/v1/certs/trusted-certificate" in api:
                async with aiofiles.open(
                    "Trusted Certificates/JSON/Trusted Certificates.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/api/v1/deployment/node" in api:
                async with aiofiles.open(
                    "Deployment Nodes/JSON/Deployment Nodes.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/api/v1/deployment/pan-ha" in api:
                async with aiofiles.open("PAN HA/JSON/PAN HA.json", mode="w") as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if f"/api/v1/node/{ self.no_https_url }/interface" in api:
                async with aiofiles.open(
                    "Node Interfaces/JSON/Node Interfaces.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if f"/api/v1/profile/{ self.no_https_url }" in api:
                async with aiofiles.open(
                    "Node Profiles/JSON/Node Profiles.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/api/v1/license/system/connection-type" in api:
                async with aiofiles.open(
                    "License Connection Type/JSON/License Connection Type.json",
                    mode="w",
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/api/v1/license/system/eval-license" in api:
                async with aiofiles.open(
                    "Eval Licenses/JSON/Eval Licenses.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/api/v1/license/system/feature-to-tier-mapping" in api:
                async with aiofiles.open(
                    "License Feature Map/JSON/License Feature Map.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/api/v1/license/system/register" in api:
                async with aiofiles.open(
                    "License Register/JSON/License Register.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/api/v1/license/system/smart-state" in api:
                async with aiofiles.open(
                    "License Smart State/JSON/License Smart State.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/api/v1/license/system/tier-state" in api:
                async with aiofiles.open(
                    "License Tier State/JSON/License Tier State.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/api/v1/patch" in api:
                async with aiofiles.open("Patches/JSON/Patches.json", mode="w") as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/api/v1/hotpatch" in api:
                async with aiofiles.open(
                    "Hot Patches/JSON/Hot Patches.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/api/v1/repository" in api:
                async with aiofiles.open(
                    "Repositories/JSON/Repositories.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/api/v1/system-settings/proxy" in api:
                async with aiofiles.open("Proxies/JSON/Proxies.json", mode="w") as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/api/v1/system-settings/telemetry/transport-gateway" in api:
                async with aiofiles.open(
                    "Transport Gateways/JSON/Transport Gateways.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/api/v1/trustsec/sgacl/nbarapp/" in api:
                async with aiofiles.open(
                    "NBAR Apps/JSON/NBAR Apps.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/api/v1/policy/device-admin/command-sets" in api:
                async with aiofiles.open(
                    "Command Sets/JSON/Command Sets.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/api/v1/policy/device-admin/condition" in api:
                async with aiofiles.open(
                    "Conditions/JSON/Conditions.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/api/v1/policy/device-admin/dictionaries/authentication" in api:
                async with aiofiles.open(
                    "Authentication Dictionaries/JSON/Authentication Dictionaries.json",
                    mode="w",
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/api/v1/policy/device-admin/dictionaries/authorization" in api:
                async with aiofiles.open(
                    "Authorization Dictionaries/JSON/Authorization Dictionaries.json",
                    mode="w",
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/api/v1/policy/device-admin/dictionaries/policyset" in api:
                async with aiofiles.open(
                    "Policy Set Dictionary/JSON/Policy Set Dictionary.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/api/v1/policy/device-admin/identity-stores" in api:
                async with aiofiles.open(
                    "Identity Stores/JSON/Identity Stores.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/api/v1/policy/device-admin/policy-set" in api:
                async with aiofiles.open(
                    "Policy Sets/JSON/Policy Sets.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/api/v1/policy/device-admin/service-names" in api:
                async with aiofiles.open(
                    "Service Names/JSON/Service Names.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/api/v1/policy/device-admin/shell-profiles" in api:
                async with aiofiles.open(
                    "Shell Profiles/JSON/Shell Profiles.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/api/v1/policy/network-access/authorization-profiles" in api:
                async with aiofiles.open(
                    "Network Authorization Profiles/JSON/Network Authorization Profiles.json",
                    mode="w",
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/api/v1/policy/network-access/condition" in api:
                if "/api/v1/policy/network-access/condition/authentication" in api:
                    async with aiofiles.open(
                        "Network Access Condition Authentication/JSON/Network Access Condition Authentication.json",
                        mode="w",
                    ) as f:
                        await f.write(json.dumps(payload, indent=4, sort_keys=True))

                elif "/api/v1/policy/network-access/condition/authorization" in api:
                    async with aiofiles.open(
                        "Network Access Condition Authorization/JSON/Network Access Condition Authorization.json",
                        mode="w",
                    ) as f:
                        await f.write(json.dumps(payload, indent=4, sort_keys=True))

                elif "/api/v1/policy/network-access/condition/policyset" in api:
                    async with aiofiles.open(
                        "Network Access Condition Policy Sets/JSON/Network Access Condition Policy Sets.json",
                        mode="w",
                    ) as f:
                        await f.write(json.dumps(payload, indent=4, sort_keys=True))
                else:
                    async with aiofiles.open(
                        "Network Access Conditions/JSON/Network Access Conditions.json",
                        mode="w",
                    ) as f:
                        await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/api/v1/policy/network-access/dictionaries" in api:
                if "/api/v1/policy/network-access/dictionaries/authentication" in api:
                    async with aiofiles.open(
                        "Network Access Dictionary Authentication/JSON/Network Access Dictionary Authentication.json",
                        mode="w",
                    ) as f:
                        await f.write(json.dumps(payload, indent=4, sort_keys=True))

                elif "/api/v1/policy/network-access/dictionaries/authorization" in api:
                    async with aiofiles.open(
                        "Network Access Dictionary Authorization/JSON/Network Access Dictionary Authorization.json",
                        mode="w",
                    ) as f:
                        await f.write(json.dumps(payload, indent=4, sort_keys=True))

                elif "/api/v1/policy/network-access/dictionaries/policyset" in api:
                    async with aiofiles.open(
                        "Network Access Dictionary Policy Sets/JSON/Network Access Dictionary Policy Sets.json",
                        mode="w",
                    ) as f:
                        await f.write(json.dumps(payload, indent=4, sort_keys=True))

                else:
                    async with aiofiles.open(
                        "Network Access Dictionaries/JSON/Network Access Dictionaries.json",
                        mode="w",
                    ) as f:
                        await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/api/v1/policy/network-access/identity-stores" in api:
                async with aiofiles.open(
                    "Network Access Identity Stores/JSON/Network Access Identity Stores.json",
                    mode="w",
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/api/v1/policy/network-access/policy-set" in api:
                async with aiofiles.open(
                    "Network Access Policy Sets/JSON/Network Access Policy Sets.json",
                    mode="w",
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/api/v1/policy/network-access/security-groups" in api:
                async with aiofiles.open(
                    "Network Access Security Groups/JSON/Network Access Security Groups.json",
                    mode="w",
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/api/v1/policy/network-access/service-names" in api:
                async with aiofiles.open(
                    "Network Access Service Names/JSON/Network Access Service Names.json",
                    mode="w",
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/admin/API/mnt/Session/ActiveCount" in api:
                async with aiofiles.open(
                    "Active Sessions/JSON/Active Sessions.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/admin/API/mnt/Session/PostureCount" in api:
                async with aiofiles.open(
                    "Posture Count/JSON/Posture Count.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/admin/API/mnt/Session/ProfilerCount" in api:
                async with aiofiles.open(
                    "Profiler Count/JSON/Profiler Count.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/admin/API/mnt/Version" in api:
                async with aiofiles.open("Version/JSON/Version.json", mode="w") as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

            if "/admin/API/mnt/FailureReasons" in api:
                async with aiofiles.open(
                    "Failure Reasons/JSON/Failure Reasons.json", mode="w"
                ) as f:
                    await f.write(json.dumps(payload, indent=4, sort_keys=True))

    async def yaml_file(self, parsed_json):
        for api, payload in json.loads(parsed_json):
            clean_yaml = yaml.dump(payload, default_flow_style=False)
            if "/ers/config/allowedprotocols" in api:
                async with aiofiles.open(
                    "Allowed Protocols/YAML/Allowed Protocols.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

            if "/ers/config/adminuser" in api:
                async with aiofiles.open(
                    "Admin Users/YAML/Admin Users.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

            if "/ers/config/activedirectory" in api:
                async with aiofiles.open(
                    "Active Directory/YAML/Active Directory.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

            if "/ers/config/authorizationprofile" in api:
                async with aiofiles.open(
                    "Authorization Profiles/YAML/Authorization Profiles.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

            if "/ers/config/downloadableacl" in api:
                async with aiofiles.open("DACLs/YAML/DACLs.yaml", mode="w") as f:
                    await f.write(clean_yaml)

            if "/ers/config/endpoint" in api:
                if "/ers/config/endpointgroup" in api:
                    async with aiofiles.open(
                        "Endpoint Groups/YAML/Endpoint Groups.yaml", mode="w"
                    ) as f:
                        await f.write(clean_yaml)
                else:
                    async with aiofiles.open(
                        "Endpoints/YAML/Endpoints.yaml", mode="w"
                    ) as f:
                        await f.write(clean_yaml)

            if "/ers/config/identitygroup" in api:
                async with aiofiles.open(
                    "Identity Groups/YAML/Identity Groups.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

            if "/ers/config/idstoresequence" in api:
                async with aiofiles.open(
                    "Identity Store Sequences/YAML/Identity Store Sequences.yaml",
                    mode="w",
                ) as f:
                    await f.write(clean_yaml)

            if "/ers/config/internaluser" in api:
                async with aiofiles.open(
                    "Internal Users/YAML/Internal Users.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

            if "/ers/config/networkdevice" in api:
                if "/ers/config/networkdevicegroup" in api:
                    async with aiofiles.open(
                        "Network Device Groups/YAML/Network Device Groups.yaml",
                        mode="w",
                    ) as f:
                        await f.write(clean_yaml)
                else:
                    async with aiofiles.open(
                        "Network Devices/YAML/Network Devices.yaml", mode="w"
                    ) as f:
                        await f.write(clean_yaml)

            if "/ers/config/node" in api:
                async with aiofiles.open("Nodes/YAML/Nodes.yaml", mode="w") as f:
                    await f.write(clean_yaml)

            if "/ers/config/portal" in api:
                async with aiofiles.open("Portals/YAML/Portals.yaml", mode="w") as f:
                    await f.write(clean_yaml)

            if "/ers/config/profilerprofile" in api:
                async with aiofiles.open(
                    "Profilers/YAML/Profilers.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

            if "/ers/config/sgt" in api:
                async with aiofiles.open("SGTs/YAML/SGTs.yaml", mode="w") as f:
                    await f.write(clean_yaml)

            if "/ers/config/sgacl" in api:
                async with aiofiles.open("SGT ACLs/YAML/SGT ACLs.yaml", mode="w") as f:
                    await f.write(clean_yaml)

            if "/ers/config/selfregportal" in api:
                async with aiofiles.open(
                    "Self Registration Portals/YAML/Self Registration Portals.yaml",
                    mode="w",
                ) as f:
                    await f.write(clean_yaml)

            if "/ers/config/sponsorgroup" in api:
                async with aiofiles.open(
                    "Sponsor Groups/YAML/Sponsor Groups.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

            if "/ers/config/sponsorportal" in api:
                async with aiofiles.open(
                    "Sponsor Portals/YAML/Sponsor Portals.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

            if "/ers/config/sponsoredguestportal" in api:
                async with aiofiles.open(
                    "Sponsored Guest Portals/YAML/Sponsored Guest Portals.yaml",
                    mode="w",
                ) as f:
                    await f.write(clean_yaml)

            if "/api/v1/backup-restore/config/last-backup-status" in api:
                async with aiofiles.open(
                    "Last Backup/YAML/Last Backup.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

            if "/api/v1/certs/certificate-signing-request" in api:
                async with aiofiles.open("CSRs/YAML/CSRs.yaml", mode="w") as f:
                    await f.write(clean_yaml)

            if "/api/v1/certs/system-certificate" in api:
                async with aiofiles.open(
                    "System Certificates/YAML/System Certificates.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

            if "/api/v1/certs/trusted-certificate" in api:
                async with aiofiles.open(
                    "Trusted Certificates/YAML/Trusted Certificates.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

            if "/api/v1/deployment/node" in api:
                async with aiofiles.open(
                    "Deployment Nodes/YAML/Deployment Nodes.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

            if "/api/v1/deployment/pan-ha" in api:
                async with aiofiles.open("PAN HA/YAML/PAN HA.yaml", mode="w") as f:
                    await f.write(clean_yaml)

            if f"/api/v1/node/{ self.no_https_url }/interface" in api:
                async with aiofiles.open(
                    "Node Interfaces/YAML/Node Interfaces.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

            if f"/api/v1/profile/{ self.no_https_url }" in api:
                async with aiofiles.open(
                    "Node Profiles/YAML/Node Profiles.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

            if "/api/v1/license/system/connection-type" in api:
                async with aiofiles.open(
                    "License Connection Type/YAML/License Connection Type.yaml",
                    mode="w",
                ) as f:
                    await f.write(clean_yaml)

            if "/api/v1/license/system/eval-license" in api:
                async with aiofiles.open(
                    "Eval Licenses/YAML/Eval Licenses.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

            if "/api/v1/license/system/feature-to-tier-mapping" in api:
                async with aiofiles.open(
                    "License Feature Map/YAML/License Feature Map.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

            if "/api/v1/license/system/register" in api:
                async with aiofiles.open(
                    "License Register/YAML/License Register.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

            if "/api/v1/license/system/smart-state" in api:
                async with aiofiles.open(
                    "License Smart State/YAML/License Smart State.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

            if "/api/v1/license/system/tier-state" in api:
                async with aiofiles.open(
                    "License Tier State/YAML/License Tier State.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

            if "/api/v1/patch" in api:
                async with aiofiles.open("Patches/YAML/Patches.yaml", mode="w") as f:
                    await f.write(clean_yaml)

            if "/api/v1/hotpatch" in api:
                async with aiofiles.open(
                    "Hot Patches/YAML/Hot Patches.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

            if "/api/v1/repository" in api:
                async with aiofiles.open(
                    "Repositories/YAML/Repositories.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

            if "/api/v1/system-settings/proxy" in api:
                async with aiofiles.open("Proxies/YAML/Proxies.yaml", mode="w") as f:
                    await f.write(clean_yaml)

            if "/api/v1/system-settings/telemetry/transport-gateway" in api:
                async with aiofiles.open(
                    "Transport Gateways/YAML/Transport Gateways.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

            if "/api/v1/trustsec/sgacl/nbarapp/" in api:
                async with aiofiles.open(
                    "NBAR Apps/YAML/NBAR Apps.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

            if "/api/v1/policy/device-admin/command-sets" in api:
                async with aiofiles.open(
                    "Command Sets/YAML/Command Sets.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

            if "/api/v1/policy/device-admin/condition" in api:
                async with aiofiles.open(
                    "Conditions/YAML/Conditions.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

            if "/api/v1/policy/device-admin/dictionaries/authentication" in api:
                async with aiofiles.open(
                    "Authentication Dictionaries/YAML/Authentication Dictionaries.yaml",
                    mode="w",
                ) as f:
                    await f.write(clean_yaml)

            if "/api/v1/policy/device-admin/dictionaries/authorization" in api:
                async with aiofiles.open(
                    "Authorization Dictionaries/YAML/Authorization Dictionaries.yaml",
                    mode="w",
                ) as f:
                    await f.write(clean_yaml)

            if "/api/v1/policy/device-admin/dictionaries/policyset" in api:
                async with aiofiles.open(
                    "Policy Set Dictionary/YAML/Policy Set Dictionary.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

            if "/api/v1/policy/device-admin/identity-stores" in api:
                async with aiofiles.open(
                    "Identity Stores/YAML/Identity Stores.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

            if "/api/v1/policy/device-admin/policy-set" in api:
                async with aiofiles.open(
                    "Policy Sets/YAML/Policy Sets.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

            if "/api/v1/policy/device-admin/service-names" in api:
                async with aiofiles.open(
                    "Service Names/YAML/Service Names.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

            if "/api/v1/policy/device-admin/shell-profiles" in api:
                async with aiofiles.open(
                    "Shell Profiles/YAML/Shell Profiles.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

            if "/api/v1/policy/network-access/authorization-profiles" in api:
                async with aiofiles.open(
                    "Network Authorization Profiles/YAML/Network Authorization Profiles.yaml",
                    mode="w",
                ) as f:
                    await f.write(clean_yaml)

            if "/api/v1/policy/network-access/condition" in api:
                if "/api/v1/policy/network-access/condition/authentication" in api:
                    async with aiofiles.open(
                        "Network Access Condition Authentication/YAML/Network Access Condition Authentication.yaml",
                        mode="w",
                    ) as f:
                        await f.write(clean_yaml)

                elif "/api/v1/policy/network-access/condition/authorization" in api:
                    async with aiofiles.open(
                        "Network Access Condition Authorization/YAML/Network Access Condition Authorization.yaml",
                        mode="w",
                    ) as f:
                        await f.write(clean_yaml)

                elif "/api/v1/policy/network-access/condition/policyset" in api:
                    async with aiofiles.open(
                        "Network Access Condition Policy Sets/YAML/Network Access Condition Policy Sets.yaml",
                        mode="w",
                    ) as f:
                        await f.write(clean_yaml)
                else:
                    async with aiofiles.open(
                        "Network Access Conditions/YAML/Network Access Conditions.yaml",
                        mode="w",
                    ) as f:
                        await f.write(clean_yaml)

            if "/api/v1/policy/network-access/dictionaries" in api:
                if "/api/v1/policy/network-access/dictionaries/authentication" in api:
                    async with aiofiles.open(
                        "Network Access Dictionary Authentication/YAML/Network Access Dictionary Authentication.yaml",
                        mode="w",
                    ) as f:
                        await f.write(clean_yaml)

                elif "/api/v1/policy/network-access/dictionaries/authorization" in api:
                    async with aiofiles.open(
                        "Network Access Dictionary Authorization/YAML/Network Access Dictionary Authorization.yaml",
                        mode="w",
                    ) as f:
                        await f.write(clean_yaml)

                elif "/api/v1/policy/network-access/dictionaries/policyset" in api:
                    async with aiofiles.open(
                        "Network Access Dictionary Policy Sets/YAML/Network Access Dictionary Policy Sets.yaml",
                        mode="w",
                    ) as f:
                        await f.write(clean_yaml)

                else:
                    async with aiofiles.open(
                        "Network Access Dictionaries/YAML/Network Access Dictionaries.yaml",
                        mode="w",
                    ) as f:
                        await f.write(clean_yaml)

            if "/api/v1/policy/network-access/identity-stores" in api:
                async with aiofiles.open(
                    "Network Access Identity Stores/YAML/Network Access Identity Stores.yaml",
                    mode="w",
                ) as f:
                    await f.write(clean_yaml)

            if "/api/v1/policy/network-access/policy-set" in api:
                async with aiofiles.open(
                    "Network Access Policy Sets/YAML/Network Access Policy Sets.yaml",
                    mode="w",
                ) as f:
                    await f.write(clean_yaml)

            if "/api/v1/policy/network-access/security-groups" in api:
                async with aiofiles.open(
                    "Network Access Security Groups/YAML/Network Access Security Groups.yaml",
                    mode="w",
                ) as f:
                    await f.write(clean_yaml)

            if "/api/v1/policy/network-access/service-names" in api:
                async with aiofiles.open(
                    "Network Access Service Names/YAML/Network Access Service Names.yaml",
                    mode="w",
                ) as f:
                    await f.write(clean_yaml)

            if "/admin/API/mnt/Session/ActiveCount" in api:
                async with aiofiles.open(
                    "Active Sessions/YAML/Active Sessions.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

            if "/admin/API/mnt/Session/PostureCount" in api:
                async with aiofiles.open(
                    "Posture Count/YAML/Posture Count.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

            if "/admin/API/mnt/Session/ProfilerCount" in api:
                async with aiofiles.open(
                    "Profiler Count/YAML/Profiler Count.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

            if "/admin/API/mnt/Version" in api:
                async with aiofiles.open("Version/YAML/Version.yaml", mode="w") as f:
                    await f.write(clean_yaml)

            if "/admin/API/mnt/FailureReasons" in api:
                async with aiofiles.open(
                    "Failure Reasons/YAML/Failure Reasons.yaml", mode="w"
                ) as f:
                    await f.write(clean_yaml)

    async def csv_file(self, parsed_json):
        template_dir = Path(__file__).resolve().parent
        env = Environment(loader=FileSystemLoader(str(template_dir)), enable_async=True)
        csv_template = env.get_template("ise_csv.j2")
        for api, payload in json.loads(parsed_json):
            csv_output = await csv_template.render_async(
                api=api, data_to_template=payload
            )
            if "/ers/config/allowedprotocols" in api:
                async with aiofiles.open(
                    "Allowed Protocols/CSV/Allowed Protocols.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

            if "/ers/config/adminuser" in api:
                async with aiofiles.open(
                    "Admin Users/CSV/Admin Users.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

            if "/ers/config/activedirectory" in api:
                async with aiofiles.open(
                    "Active Directory/CSV/Active Directory.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

            if "/ers/config/authorizationprofile" in api:
                async with aiofiles.open(
                    "Authorization Profiles/CSV/Authorization Profiles.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

            if "/ers/config/downloadableacl" in api:
                async with aiofiles.open("DACLs/CSV/DACLs.csv", mode="w") as f:
                    await f.write(csv_output)

            if "/ers/config/endpoint" in api:
                if "/ers/config/endpointgroup" in api:
                    async with aiofiles.open(
                        "Endpoint Groups/CSV/Endpoint Groups.csv", mode="w"
                    ) as f:
                        await f.write(csv_output)
                else:
                    async with aiofiles.open(
                        "Endpoints/CSV/Endpoints.csv", mode="w"
                    ) as f:
                        await f.write(csv_output)

            if "/ers/config/identitygroup" in api:
                async with aiofiles.open(
                    "Identity Groups/CSV/Identity Groups.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

            if "/ers/config/idstoresequence" in api:
                async with aiofiles.open(
                    "Identity Store Sequences/CSV/Identity Store Sequences.csv",
                    mode="w",
                ) as f:
                    await f.write(csv_output)

            if "/ers/config/internaluser" in api:
                async with aiofiles.open(
                    "Internal Users/CSV/Internal Users.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

            if "/ers/config/networkdevice" in api:
                if "/ers/config/networkdevicegroup" in api:
                    async with aiofiles.open(
                        "Network Device Groups/CSV/Network Device Groups.csv", mode="w"
                    ) as f:
                        await f.write(csv_output)
                else:
                    async with aiofiles.open(
                        "Network Devices/CSV/Network Devices.csv", mode="w"
                    ) as f:
                        await f.write(csv_output)

            if "/ers/config/node" in api:
                async with aiofiles.open("Nodes/CSV/Nodes.csv", mode="w") as f:
                    await f.write(csv_output)

            if "/ers/config/portal" in api:
                async with aiofiles.open("Portals/CSV/Portals.csv", mode="w") as f:
                    await f.write(csv_output)

            if "/ers/config/profilerprofile" in api:
                async with aiofiles.open("Profilers/CSV/Profilers.csv", mode="w") as f:
                    await f.write(csv_output)

            if "/ers/config/sgt" in api:
                async with aiofiles.open("SGTs/CSV/SGTs.csv", mode="w") as f:
                    await f.write(csv_output)

            if "/ers/config/sgacl" in api:
                async with aiofiles.open("SGT ACLs/CSV/SGT ACLs.csv", mode="w") as f:
                    await f.write(csv_output)

            if "/ers/config/selfregportal" in api:
                async with aiofiles.open(
                    "Self Registration Portals/CSV/Self Registration Portals.csv",
                    mode="w",
                ) as f:
                    await f.write(csv_output)

            if "/ers/config/sponsorgroup" in api:
                async with aiofiles.open(
                    "Sponsor Groups/CSV/Sponsor Groups.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

            if "/ers/config/sponsorportal" in api:
                async with aiofiles.open(
                    "Sponsor Portals/CSV/Sponsor Portals.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

            if "/ers/config/sponsoredguestportal" in api:
                async with aiofiles.open(
                    "Sponsored Guest Portals/CSV/Sponsored Guest Portals.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

            if "/api/v1/backup-restore/config/last-backup-status" in api:
                async with aiofiles.open(
                    "Last Backup/CSV/Last Backup.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

            if "/api/v1/certs/certificate-signing-request" in api:
                async with aiofiles.open("CSRs/CSV/CSRs.csv", mode="w") as f:
                    await f.write(csv_output)

            if "/api/v1/certs/system-certificate" in api:
                async with aiofiles.open(
                    "System Certificates/CSV/System Certificates.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

            if "/api/v1/certs/trusted-certificate" in api:
                async with aiofiles.open(
                    "Trusted Certificates/CSV/Trusted Certificates.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

            if "/api/v1/deployment/node" in api:
                async with aiofiles.open(
                    "Deployment Nodes/CSV/Deployment Nodes.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

            if "/api/v1/deployment/pan-ha" in api:
                async with aiofiles.open("PAN HA/CSV/PAN HA.csv", mode="w") as f:
                    await f.write(csv_output)

            if f"/api/v1/node/{ self.no_https_url }/interface" in api:
                async with aiofiles.open(
                    "Node Interfaces/CSV/Node Interfaces.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

            if f"/api/v1/profile/{ self.no_https_url }" in api:
                async with aiofiles.open(
                    "Node Profiles/CSV/Node Profiles.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

            if "/api/v1/license/system/connection-type" in api:
                async with aiofiles.open(
                    "License Connection Type/CSV/License Connection Type.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

            if "/api/v1/license/system/eval-license" in api:
                async with aiofiles.open(
                    "Eval Licenses/CSV/Eval Licenses.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

            if "/api/v1/license/system/feature-to-tier-mapping" in api:
                async with aiofiles.open(
                    "License Feature Map/CSV/License Feature Map.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

            if "/api/v1/license/system/register" in api:
                async with aiofiles.open(
                    "License Register/CSV/License Register.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

            if "/api/v1/license/system/smart-state" in api:
                async with aiofiles.open(
                    "License Smart State/CSV/License Smart State.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

            if "/api/v1/license/system/tier-state" in api:
                async with aiofiles.open(
                    "License Tier State/CSV/License Tier State.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

            if "/api/v1/patch" in api:
                async with aiofiles.open("Patches/CSV/Patches.csv", mode="w") as f:
                    await f.write(csv_output)

            if "/api/v1/hotpatch" in api:
                async with aiofiles.open(
                    "Hot Patches/CSV/Hot Patches.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

            if "/api/v1/repository" in api:
                async with aiofiles.open(
                    "Repositories/CSV/Repositories.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

            if "/api/v1/system-settings/proxy" in api:
                async with aiofiles.open("Proxies/CSV/Proxies.csv", mode="w") as f:
                    await f.write(csv_output)

            if "/api/v1/system-settings/telemetry/transport-gateway" in api:
                async with aiofiles.open(
                    "Transport Gateways/CSV/Transport Gateways.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

            if "/api/v1/trustsec/sgacl/nbarapp/" in api:
                async with aiofiles.open("NBAR Apps/CSV/NBAR Apps.csv", mode="w") as f:
                    await f.write(csv_output)

            if "/api/v1/policy/device-admin/command-sets" in api:
                async with aiofiles.open(
                    "Command Sets/CSV/Command Sets.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

            if "/api/v1/policy/device-admin/condition" in api:
                async with aiofiles.open(
                    "Conditions/CSV/Conditions.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

            if "/api/v1/policy/device-admin/dictionaries/authentication" in api:
                async with aiofiles.open(
                    "Authentication Dictionaries/CSV/Authentication Dictionaries.csv",
                    mode="w",
                ) as f:
                    await f.write(csv_output)

            if "/api/v1/policy/device-admin/dictionaries/authorization" in api:
                async with aiofiles.open(
                    "Authorization Dictionaries/CSV/Authorization Dictionaries.csv",
                    mode="w",
                ) as f:
                    await f.write(csv_output)

            if "/api/v1/policy/device-admin/dictionaries/policyset" in api:
                async with aiofiles.open(
                    "Policy Set Dictionary/CSV/Policy Set Dictionary.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

            if "/api/v1/policy/device-admin/identity-stores" in api:
                async with aiofiles.open(
                    "Identity Stores/CSV/Identity Stores.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

            if "/api/v1/policy/device-admin/policy-set" in api:
                async with aiofiles.open(
                    "Policy Sets/CSV/Policy Sets.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

            if "/api/v1/policy/device-admin/service-names" in api:
                async with aiofiles.open(
                    "Service Names/CSV/Service Names.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

            if "/api/v1/policy/device-admin/shell-profiles" in api:
                async with aiofiles.open(
                    "Shell Profiles/CSV/Shell Profiles.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

            if "/api/v1/policy/network-access/authorization-profiles" in api:
                async with aiofiles.open(
                    "Network Authorization Profiles/CSV/Network Authorization Profiles.csv",
                    mode="w",
                ) as f:
                    await f.write(csv_output)

            if "/api/v1/policy/network-access/condition" in api:
                if "/api/v1/policy/network-access/condition/authentication" in api:
                    async with aiofiles.open(
                        "Network Access Condition Authentication/CSV/Network Access Condition Authentication.csv",
                        mode="w",
                    ) as f:
                        await f.write(csv_output)

                elif "/api/v1/policy/network-access/condition/authorization" in api:
                    async with aiofiles.open(
                        "Network Access Condition Authorization/CSV/Network Access Condition Authorization.csv",
                        mode="w",
                    ) as f:
                        await f.write(csv_output)

                elif "/api/v1/policy/network-access/condition/policyset" in api:
                    async with aiofiles.open(
                        "Network Access Condition Policy Sets/CSV/Network Access Condition Policy Sets.csv",
                        mode="w",
                    ) as f:
                        await f.write(csv_output)
                else:
                    async with aiofiles.open(
                        "Network Access Conditions/CSV/Network Access Conditions.csv",
                        mode="w",
                    ) as f:
                        await f.write(csv_output)

            if "/api/v1/policy/network-access/dictionaries" in api:
                if "/api/v1/policy/network-access/dictionaries/authentication" in api:
                    async with aiofiles.open(
                        "Network Access Dictionary Authentication/CSV/Network Access Dictionary Authentication.csv",
                        mode="w",
                    ) as f:
                        await f.write(csv_output)

                elif "/api/v1/policy/network-access/dictionaries/authorization" in api:
                    async with aiofiles.open(
                        "Network Access Dictionary Authorization/CSV/Network Access Dictionary Authorization.csv",
                        mode="w",
                    ) as f:
                        await f.write(csv_output)

                elif "/api/v1/policy/network-access/dictionaries/policyset" in api:
                    async with aiofiles.open(
                        "Network Access Dictionary Policy Sets/CSV/Network Access Dictionary Policy Sets.csv",
                        mode="w",
                    ) as f:
                        await f.write(csv_output)

                else:
                    async with aiofiles.open(
                        "Network Access Dictionaries/CSV/Network Access Dictionaries.csv",
                        mode="w",
                    ) as f:
                        await f.write(csv_output)

            if "/api/v1/policy/network-access/identity-stores" in api:
                async with aiofiles.open(
                    "Network Access Identity Stores/CSV/Network Access Identity Stores.csv",
                    mode="w",
                ) as f:
                    await f.write(csv_output)

            if "/api/v1/policy/network-access/policy-set" in api:
                async with aiofiles.open(
                    "Network Access Policy Sets/CSV/Network Access Policy Sets.csv",
                    mode="w",
                ) as f:
                    await f.write(csv_output)

            if "/api/v1/policy/network-access/security-groups" in api:
                async with aiofiles.open(
                    "Network Access Security Groups/CSV/Network Access Security Groups.csv",
                    mode="w",
                ) as f:
                    await f.write(csv_output)

            if "/api/v1/policy/network-access/service-names" in api:
                async with aiofiles.open(
                    "Network Access Service Names/CSV/Network Access Service Names.csv",
                    mode="w",
                ) as f:
                    await f.write(csv_output)

            if "/admin/API/mnt/Session/ActiveCount" in api:
                async with aiofiles.open(
                    "Active Sessions/CSV/Active Sessions.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

            if "/admin/API/mnt/Session/PostureCount" in api:
                async with aiofiles.open(
                    "Posture Count/CSV/Posture Count.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

            if "/admin/API/mnt/Session/ProfilerCount" in api:
                async with aiofiles.open(
                    "Profiler Count/CSV/Profiler Count.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

            if "/admin/API/mnt/Version" in api:
                async with aiofiles.open("Version/CSV/Version.csv", mode="w") as f:
                    await f.write(csv_output)

            if "/admin/API/mnt/FailureReasons" in api:
                async with aiofiles.open(
                    "Failure Reasons/CSV/Failure Reasons.csv", mode="w"
                ) as f:
                    await f.write(csv_output)

    async def markdown_file(self, parsed_json):
        template_dir = Path(__file__).resolve().parent
        env = Environment(loader=FileSystemLoader(str(template_dir)), enable_async=True)
        markdown_template = env.get_template("ise_markdown.j2")
        for api, payload in json.loads(parsed_json):
            markdown_output = await markdown_template.render_async(
                api=api, data_to_template=payload
            )
            if "/ers/config/allowedprotocols" in api:
                async with aiofiles.open(
                    "Allowed Protocols/Markdown/Allowed Protocols.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

            if "/ers/config/adminuser" in api:
                async with aiofiles.open(
                    "Admin Users/Markdown/Admin Users.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

            if "/ers/config/activedirectory" in api:
                async with aiofiles.open(
                    "Active Directory/Markdown/Active Directory.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

            if "/ers/config/authorizationprofile" in api:
                async with aiofiles.open(
                    "Authorization Profiles/Markdown/Authorization Profiles.md",
                    mode="w",
                ) as f:
                    await f.write(markdown_output)

            if "/ers/config/downloadableacl" in api:
                async with aiofiles.open("DACLs/Markdown/DACLs.md", mode="w") as f:
                    await f.write(markdown_output)

            if "/ers/config/endpoint" in api:
                if "/ers/config/endpointgroup" in api:
                    async with aiofiles.open(
                        "Endpoint Groups/Markdown/Endpoint Groups.md", mode="w"
                    ) as f:
                        await f.write(markdown_output)
                else:
                    async with aiofiles.open(
                        "Endpoints/Markdown/Endpoints.md", mode="w"
                    ) as f:
                        await f.write(markdown_output)

            if "/ers/config/identitygroup" in api:
                async with aiofiles.open(
                    "Identity Groups/Markdown/Identity Groups.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

            if "/ers/config/idstoresequence" in api:
                async with aiofiles.open(
                    "Identity Store Sequences/Markdown/Identity Store Sequences.md",
                    mode="w",
                ) as f:
                    await f.write(markdown_output)

            if "/ers/config/internaluser" in api:
                async with aiofiles.open(
                    "Internal Users/Markdown/Internal Users.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

            if "/ers/config/networkdevice" in api:
                if "/ers/config/networkdevicegroup" in api:
                    async with aiofiles.open(
                        "Network Device Groups/Markdown/Network Device Groups.md",
                        mode="w",
                    ) as f:
                        await f.write(markdown_output)
                else:
                    async with aiofiles.open(
                        "Network Devices/Markdown/Network Devices.md", mode="w"
                    ) as f:
                        await f.write(markdown_output)

            if "/ers/config/node" in api:
                async with aiofiles.open("Nodes/Markdown/Nodes.md", mode="w") as f:
                    await f.write(markdown_output)

            if "/ers/config/portal" in api:
                async with aiofiles.open("Portals/Markdown/Portals.md", mode="w") as f:
                    await f.write(markdown_output)

            if "/ers/config/profilerprofile" in api:
                async with aiofiles.open(
                    "Profilers/Markdown/Profilers.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

            if "/ers/config/sgt" in api:
                async with aiofiles.open("SGTs/Markdown/SGTs.md", mode="w") as f:
                    await f.write(markdown_output)

            if "/ers/config/sgacl" in api:
                async with aiofiles.open(
                    "SGT ACLs/Markdown/SGT ACLs.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

            if "/ers/config/selfregportal" in api:
                async with aiofiles.open(
                    "Self Registration Portals/Markdown/Self Registration Portals.md",
                    mode="w",
                ) as f:
                    await f.write(markdown_output)

            if "/ers/config/sponsorgroup" in api:
                async with aiofiles.open(
                    "Sponsor Groups/Markdown/Sponsor Groups.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

            if "/ers/config/sponsorportal" in api:
                async with aiofiles.open(
                    "Sponsor Portals/Markdown/Sponsor Portals.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

            if "/ers/config/sponsoredguestportal" in api:
                async with aiofiles.open(
                    "Sponsored Guest Portals/Markdown/Sponsored Guest Portals.md",
                    mode="w",
                ) as f:
                    await f.write(markdown_output)

            if "/api/v1/backup-restore/config/last-backup-status" in api:
                async with aiofiles.open(
                    "Last Backup/Markdown/Last Backup.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

            if "/api/v1/certs/certificate-signing-request" in api:
                async with aiofiles.open("CSRs/Markdown/CSRs.md", mode="w") as f:
                    await f.write(markdown_output)

            if "/api/v1/certs/system-certificate" in api:
                async with aiofiles.open(
                    "System Certificates/Markdown/System Certificates.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

            if "/api/v1/certs/trusted-certificate" in api:
                async with aiofiles.open(
                    "Trusted Certificates/Markdown/Trusted Certificates.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

            if "/api/v1/deployment/node" in api:
                async with aiofiles.open(
                    "Deployment Nodes/Markdown/Deployment Nodes.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

            if "/api/v1/deployment/pan-ha" in api:
                async with aiofiles.open("PAN HA/Markdown/PAN HA.md", mode="w") as f:
                    await f.write(markdown_output)

            if f"/api/v1/node/{ self.no_https_url }/interface" in api:
                async with aiofiles.open(
                    "Node Interfaces/Markdown/Node Interfaces.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

            if f"/api/v1/profile/{ self.no_https_url }" in api:
                async with aiofiles.open(
                    "Node Profiles/Markdown/Node Profiles.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

            if "/api/v1/license/system/connection-type" in api:
                async with aiofiles.open(
                    "License Connection Type/Markdown/License Connection Type.md",
                    mode="w",
                ) as f:
                    await f.write(markdown_output)

            if "/api/v1/license/system/eval-license" in api:
                async with aiofiles.open(
                    "Eval Licenses/Markdown/Eval Licenses.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

            if "/api/v1/license/system/feature-to-tier-mapping" in api:
                async with aiofiles.open(
                    "License Feature Map/Markdown/License Feature Map.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

            if "/api/v1/license/system/register" in api:
                async with aiofiles.open(
                    "License Register/Markdown/License Register.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

            if "/api/v1/license/system/smart-state" in api:
                async with aiofiles.open(
                    "License Smart State/Markdown/License Smart State.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

            if "/api/v1/license/system/tier-state" in api:
                async with aiofiles.open(
                    "License Tier State/Markdown/License Tier State.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

            if "/api/v1/patch" in api:
                async with aiofiles.open("Patches/Markdown/Patches.md", mode="w") as f:
                    await f.write(markdown_output)

            if "/api/v1/hotpatch" in api:
                async with aiofiles.open(
                    "Hot Patches/Markdown/Hot Patches.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

            if "/api/v1/repository" in api:
                async with aiofiles.open(
                    "Repositories/Markdown/Repositories.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

            if "/api/v1/system-settings/proxy" in api:
                async with aiofiles.open("Proxies/Markdown/Proxies.md", mode="w") as f:
                    await f.write(markdown_output)

            if "/api/v1/system-settings/telemetry/transport-gateway" in api:
                async with aiofiles.open(
                    "Transport Gateways/Markdown/Transport Gateways.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

            if "/api/v1/trustsec/sgacl/nbarapp/" in api:
                async with aiofiles.open(
                    "NBAR Apps/Markdown/NBAR Apps.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

            if "/api/v1/policy/device-admin/command-sets" in api:
                async with aiofiles.open(
                    "Command Sets/Markdown/Command Sets.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

            if "/api/v1/policy/device-admin/condition" in api:
                async with aiofiles.open(
                    "Conditions/Markdown/Conditions.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

            if "/api/v1/policy/device-admin/dictionaries/authentication" in api:
                async with aiofiles.open(
                    "Authentication Dictionaries/Markdown/Authentication Dictionaries.md",
                    mode="w",
                ) as f:
                    await f.write(markdown_output)

            if "/api/v1/policy/device-admin/dictionaries/authorization" in api:
                async with aiofiles.open(
                    "Authorization Dictionaries/Markdown/Authorization Dictionaries.md",
                    mode="w",
                ) as f:
                    await f.write(markdown_output)

            if "/api/v1/policy/device-admin/dictionaries/policyset" in api:
                async with aiofiles.open(
                    "Policy Set Dictionary/Markdown/Policy Set Dictionary.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

            if "/api/v1/policy/device-admin/identity-stores" in api:
                async with aiofiles.open(
                    "Identity Stores/Markdown/Identity Stores.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

            if "/api/v1/policy/device-admin/policy-set" in api:
                async with aiofiles.open(
                    "Policy Sets/Markdown/Policy Sets.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

            if "/api/v1/policy/device-admin/service-names" in api:
                async with aiofiles.open(
                    "Service Names/Markdown/Service Names.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

            if "/api/v1/policy/device-admin/shell-profiles" in api:
                async with aiofiles.open(
                    "Shell Profiles/Markdown/Shell Profiles.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

            if "/api/v1/policy/network-access/authorization-profiles" in api:
                async with aiofiles.open(
                    "Network Authorization Profiles/Markdown/Network Authorization Profiles.md",
                    mode="w",
                ) as f:
                    await f.write(markdown_output)

            if "/api/v1/policy/network-access/condition" in api:
                if "/api/v1/policy/network-access/condition/authentication" in api:
                    async with aiofiles.open(
                        "Network Access Condition Authentication/Markdown/Network Access Condition Authentication.md",
                        mode="w",
                    ) as f:
                        await f.write(markdown_output)

                elif "/api/v1/policy/network-access/condition/authorization" in api:
                    async with aiofiles.open(
                        "Network Access Condition Authorization/Markdown/Network Access Condition Authorization.md",
                        mode="w",
                    ) as f:
                        await f.write(markdown_output)

                elif "/api/v1/policy/network-access/condition/policyset" in api:
                    async with aiofiles.open(
                        "Network Access Condition Policy Sets/Markdown/Network Access Condition Policy Sets.md",
                        mode="w",
                    ) as f:
                        await f.write(markdown_output)
                else:
                    async with aiofiles.open(
                        "Network Access Conditions/Markdown/Network Access Conditions.md",
                        mode="w",
                    ) as f:
                        await f.write(markdown_output)

            if "/api/v1/policy/network-access/dictionaries" in api:
                if "/api/v1/policy/network-access/dictionaries/authentication" in api:
                    async with aiofiles.open(
                        "Network Access Dictionary Authentication/Markdown/Network Access Dictionary Authentication.md",
                        mode="w",
                    ) as f:
                        await f.write(markdown_output)

                elif "/api/v1/policy/network-access/dictionaries/authorization" in api:
                    async with aiofiles.open(
                        "Network Access Dictionary Authorization/Markdown/Network Access Dictionary Authorization.md",
                        mode="w",
                    ) as f:
                        await f.write(markdown_output)

                elif "/api/v1/policy/network-access/dictionaries/policyset" in api:
                    async with aiofiles.open(
                        "Network Access Dictionary Policy Sets/Markdown/Network Access Dictionary Policy Sets.md",
                        mode="w",
                    ) as f:
                        await f.write(markdown_output)

                else:
                    async with aiofiles.open(
                        "Network Access Dictionaries/Markdown/Network Access Dictionaries.md",
                        mode="w",
                    ) as f:
                        await f.write(markdown_output)

            if "/api/v1/policy/network-access/identity-stores" in api:
                async with aiofiles.open(
                    "Network Access Identity Stores/Markdown/Network Access Identity Stores.md",
                    mode="w",
                ) as f:
                    await f.write(markdown_output)

            if "/api/v1/policy/network-access/policy-set" in api:
                async with aiofiles.open(
                    "Network Access Policy Sets/Markdown/Network Access Policy Sets.md",
                    mode="w",
                ) as f:
                    await f.write(markdown_output)

            if "/api/v1/policy/network-access/security-groups" in api:
                async with aiofiles.open(
                    "Network Access Security Groups/Markdown/Network Access Security Groups.md",
                    mode="w",
                ) as f:
                    await f.write(markdown_output)

            if "/api/v1/policy/network-access/service-names" in api:
                async with aiofiles.open(
                    "Network Access Service Names/Markdown/Network Access Service Names.md",
                    mode="w",
                ) as f:
                    await f.write(markdown_output)

            if "/admin/API/mnt/Session/ActiveCount" in api:
                async with aiofiles.open(
                    "Active Sessions/Markdown/Active Sessions.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

            if "/admin/API/mnt/Session/PostureCount" in api:
                async with aiofiles.open(
                    "Posture Count/Markdown/Posture Count.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

            if "/admin/API/mnt/Session/ProfilerCount" in api:
                async with aiofiles.open(
                    "Profiler Count/Markdown/Profiler Count.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

            if "/admin/API/mnt/Version" in api:
                async with aiofiles.open("Version/Markdown/Version.md", mode="w") as f:
                    await f.write(markdown_output)

            if "/admin/API/mnt/FailureReasons" in api:
                async with aiofiles.open(
                    "Failure Reasons/Markdown/Failure Reasons.md", mode="w"
                ) as f:
                    await f.write(markdown_output)

    async def html_file(self, parsed_json):
        template_dir = Path(__file__).resolve().parent
        env = Environment(loader=FileSystemLoader(str(template_dir)), enable_async=True)
        html_template = env.get_template("ise_html.j2")
        for api, payload in json.loads(parsed_json):
            html_output = await html_template.render_async(
                api=api, data_to_template=payload
            )
            if "/ers/config/allowedprotocols" in api:
                async with aiofiles.open(
                    "Allowed Protocols/HTML/Allowed Protocols.html", mode="w"
                ) as f:
                    await f.write(html_output)

            if "/ers/config/adminuser" in api:
                async with aiofiles.open(
                    "Admin Users/HTML/Admin Users.html", mode="w"
                ) as f:
                    await f.write(html_output)

            if "/ers/config/activedirectory" in api:
                async with aiofiles.open(
                    "Active Directory/HTML/Active Directory.html", mode="w"
                ) as f:
                    await f.write(html_output)

            if "/ers/config/authorizationprofile" in api:
                async with aiofiles.open(
                    "Authorization Profiles/HTML/Authorization Profiles.html", mode="w"
                ) as f:
                    await f.write(html_output)

            if "/ers/config/downloadableacl" in api:
                async with aiofiles.open("DACLs/HTML/DACLs.html", mode="w") as f:
                    await f.write(html_output)

            if "/ers/config/endpoint" in api:
                if "/ers/config/endpointgroup" in api:
                    async with aiofiles.open(
                        "Endpoint Groups/HTML/Endpoint Groups.html", mode="w"
                    ) as f:
                        await f.write(html_output)
                else:
                    async with aiofiles.open(
                        "Endpoints/HTML/Endpoints.html", mode="w"
                    ) as f:
                        await f.write(html_output)

            if "/ers/config/identitygroup" in api:
                async with aiofiles.open(
                    "Identity Groups/HTML/Identity Groups.html", mode="w"
                ) as f:
                    await f.write(html_output)

            if "/ers/config/idstoresequence" in api:
                async with aiofiles.open(
                    "Identity Store Sequences/HTML/Identity Store Sequences.html",
                    mode="w",
                ) as f:
                    await f.write(html_output)

            if "/ers/config/internaluser" in api:
                async with aiofiles.open(
                    "Internal Users/HTML/Internal Users.html", mode="w"
                ) as f:
                    await f.write(html_output)

            if "/ers/config/networkdevice" in api:
                if "/ers/config/networkdevicegroup" in api:
                    async with aiofiles.open(
                        "Network Device Groups/HTML/Network Device Groups.html",
                        mode="w",
                    ) as f:
                        await f.write(html_output)
                else:
                    async with aiofiles.open(
                        "Network Devices/HTML/Network Devices.html", mode="w"
                    ) as f:
                        await f.write(html_output)

            if "/ers/config/node" in api:
                async with aiofiles.open("Nodes/HTML/Nodes.html", mode="w") as f:
                    await f.write(html_output)

            if "/ers/config/portal" in api:
                async with aiofiles.open("Portals/HTML/Portals.html", mode="w") as f:
                    await f.write(html_output)

            if "/ers/config/profilerprofile" in api:
                async with aiofiles.open(
                    "Profilers/HTML/Profilers.html", mode="w"
                ) as f:
                    await f.write(html_output)

            if "/ers/config/sgt" in api:
                async with aiofiles.open("SGTs/HTML/SGTs.html", mode="w") as f:
                    await f.write(html_output)

            if "/ers/config/sgacl" in api:
                async with aiofiles.open("SGT ACLs/HTML/SGT ACLs.html", mode="w") as f:
                    await f.write(html_output)

            if "/ers/config/selfregportal" in api:
                async with aiofiles.open(
                    "Self Registration Portals/HTML/Self Registration Portals.html",
                    mode="w",
                ) as f:
                    await f.write(html_output)

            if "/ers/config/sponsorgroup" in api:
                async with aiofiles.open(
                    "Sponsor Groups/HTML/Sponsor Groups.html", mode="w"
                ) as f:
                    await f.write(html_output)

            if "/ers/config/sponsorportal" in api:
                async with aiofiles.open(
                    "Sponsor Portals/HTML/Sponsor Portals.html", mode="w"
                ) as f:
                    await f.write(html_output)

            if "/ers/config/sponsoredguestportal" in api:
                async with aiofiles.open(
                    "Sponsored Guest Portals/HTML/Sponsored Guest Portals.html",
                    mode="w",
                ) as f:
                    await f.write(html_output)

            if "/api/v1/backup-restore/config/last-backup-status" in api:
                async with aiofiles.open(
                    "Last Backup/HTML/Last Backup.html", mode="w"
                ) as f:
                    await f.write(html_output)

            if "/api/v1/certs/certificate-signing-request" in api:
                async with aiofiles.open("CSRs/HTML/CSRs.html", mode="w") as f:
                    await f.write(html_output)

            if "/api/v1/certs/system-certificate" in api:
                async with aiofiles.open(
                    "System Certificates/HTML/System Certificates.html", mode="w"
                ) as f:
                    await f.write(html_output)

            if "/api/v1/certs/trusted-certificate" in api:
                async with aiofiles.open(
                    "Trusted Certificates/HTML/Trusted Certificates.html", mode="w"
                ) as f:
                    await f.write(html_output)

            if "/api/v1/deployment/node" in api:
                async with aiofiles.open(
                    "Deployment Nodes/HTML/Deployment Nodes.html", mode="w"
                ) as f:
                    await f.write(html_output)

            if "/api/v1/deployment/pan-ha" in api:
                async with aiofiles.open("PAN HA/HTML/PAN HA.html", mode="w") as f:
                    await f.write(html_output)

            if f"/api/v1/node/{ self.no_https_url }/interface" in api:
                async with aiofiles.open(
                    "Node Interfaces/HTML/Node Interfaces.html", mode="w"
                ) as f:
                    await f.write(html_output)

            if f"/api/v1/profile/{ self.no_https_url }" in api:
                async with aiofiles.open(
                    "Node Profiles/HTML/Node Profiles.html", mode="w"
                ) as f:
                    await f.write(html_output)

            if "/api/v1/license/system/connection-type" in api:
                async with aiofiles.open(
                    "License Connection Type/HTML/License Connection Type.html",
                    mode="w",
                ) as f:
                    await f.write(html_output)

            if "/api/v1/license/system/eval-license" in api:
                async with aiofiles.open(
                    "Eval Licenses/HTML/Eval Licenses.html", mode="w"
                ) as f:
                    await f.write(html_output)

            if "/api/v1/license/system/feature-to-tier-mapping" in api:
                async with aiofiles.open(
                    "License Feature Map/HTML/License Feature Map.html", mode="w"
                ) as f:
                    await f.write(html_output)

            if "/api/v1/license/system/register" in api:
                async with aiofiles.open(
                    "License Register/HTML/License Register.html", mode="w"
                ) as f:
                    await f.write(html_output)

            if "/api/v1/license/system/smart-state" in api:
                async with aiofiles.open(
                    "License Smart State/HTML/License Smart State.html", mode="w"
                ) as f:
                    await f.write(html_output)

            if "/api/v1/license/system/tier-state" in api:
                async with aiofiles.open(
                    "License Tier State/HTML/License Tier State.html", mode="w"
                ) as f:
                    await f.write(html_output)

            if "/api/v1/patch" in api:
                async with aiofiles.open("Patches/HTML/Patches.html", mode="w") as f:
                    await f.write(html_output)

            if "/api/v1/hotpatch" in api:
                async with aiofiles.open(
                    "Hot Patches/HTML/Hot Patches.html", mode="w"
                ) as f:
                    await f.write(html_output)

            if "/api/v1/repository" in api:
                async with aiofiles.open(
                    "Repositories/HTML/Repositories.html", mode="w"
                ) as f:
                    await f.write(html_output)

            if "/api/v1/system-settings/proxy" in api:
                async with aiofiles.open("Proxies/HTML/Proxies.html", mode="w") as f:
                    await f.write(html_output)

            if "/api/v1/system-settings/telemetry/transport-gateway" in api:
                async with aiofiles.open(
                    "Transport Gateways/HTML/Transport Gateways.html", mode="w"
                ) as f:
                    await f.write(html_output)

            if "/api/v1/trustsec/sgacl/nbarapp/" in api:
                async with aiofiles.open(
                    "NBAR Apps/HTML/NBAR Apps.html", mode="w"
                ) as f:
                    await f.write(html_output)

            if "/api/v1/policy/device-admin/command-sets" in api:
                async with aiofiles.open(
                    "Command Sets/HTML/Command Sets.html", mode="w"
                ) as f:
                    await f.write(html_output)

            if "/api/v1/policy/device-admin/condition" in api:
                async with aiofiles.open(
                    "Conditions/HTML/Conditions.html", mode="w"
                ) as f:
                    await f.write(html_output)

            if "/api/v1/policy/device-admin/dictionaries/authentication" in api:
                async with aiofiles.open(
                    "Authentication Dictionaries/HTML/Authentication Dictionaries.html",
                    mode="w",
                ) as f:
                    await f.write(html_output)

            if "/api/v1/policy/device-admin/dictionaries/authorization" in api:
                async with aiofiles.open(
                    "Authorization Dictionaries/HTML/Authorization Dictionaries.html",
                    mode="w",
                ) as f:
                    await f.write(html_output)

            if "/api/v1/policy/device-admin/dictionaries/policyset" in api:
                async with aiofiles.open(
                    "Policy Set Dictionary/HTML/Policy Set Dictionary.html", mode="w"
                ) as f:
                    await f.write(html_output)

            if "/api/v1/policy/device-admin/identity-stores" in api:
                async with aiofiles.open(
                    "Identity Stores/HTML/Identity Stores.html", mode="w"
                ) as f:
                    await f.write(html_output)

            if "/api/v1/policy/device-admin/policy-set" in api:
                async with aiofiles.open(
                    "Policy Sets/HTML/Policy Sets.html", mode="w"
                ) as f:
                    await f.write(html_output)

            if "/api/v1/policy/device-admin/service-names" in api:
                async with aiofiles.open(
                    "Service Names/HTML/Service Names.html", mode="w"
                ) as f:
                    await f.write(html_output)

            if "/api/v1/policy/device-admin/shell-profiles" in api:
                async with aiofiles.open(
                    "Shell Profiles/HTML/Shell Profiles.html", mode="w"
                ) as f:
                    await f.write(html_output)

            if "/api/v1/policy/network-access/authorization-profiles" in api:
                async with aiofiles.open(
                    "Network Authorization Profiles/HTML/Network Authorization Profiles.html",
                    mode="w",
                ) as f:
                    await f.write(html_output)

            if "/api/v1/policy/network-access/condition" in api:
                if "/api/v1/policy/network-access/condition/authentication" in api:
                    async with aiofiles.open(
                        "Network Access Condition Authentication/HTML/Network Access Condition Authentication.html",
                        mode="w",
                    ) as f:
                        await f.write(html_output)

                elif "/api/v1/policy/network-access/condition/authorization" in api:
                    async with aiofiles.open(
                        "Network Access Condition Authorization/HTML/Network Access Condition Authorization.html",
                        mode="w",
                    ) as f:
                        await f.write(html_output)

                elif "/api/v1/policy/network-access/condition/policyset" in api:
                    async with aiofiles.open(
                        "Network Access Condition Policy Sets/HTML/Network Access Condition Policy Sets.html",
                        mode="w",
                    ) as f:
                        await f.write(html_output)
                else:
                    async with aiofiles.open(
                        "Network Access Conditions/HTML/Network Access Conditions.html",
                        mode="w",
                    ) as f:
                        await f.write(html_output)

            if "/api/v1/policy/network-access/dictionaries" in api:
                if "/api/v1/policy/network-access/dictionaries/authentication" in api:
                    async with aiofiles.open(
                        "Network Access Dictionary Authentication/HTML/Network Access Dictionary Authentication.html",
                        mode="w",
                    ) as f:
                        await f.write(html_output)

                elif "/api/v1/policy/network-access/dictionaries/authorization" in api:
                    async with aiofiles.open(
                        "Network Access Dictionary Authorization/HTML/Network Access Dictionary Authorization.html",
                        mode="w",
                    ) as f:
                        await f.write(html_output)

                elif "/api/v1/policy/network-access/dictionaries/policyset" in api:
                    async with aiofiles.open(
                        "Network Access Dictionary Policy Sets/HTML/Network Access Dictionary Policy Sets.html",
                        mode="w",
                    ) as f:
                        await f.write(html_output)

                else:
                    async with aiofiles.open(
                        "Network Access Dictionaries/HTML/Network Access Dictionaries.html",
                        mode="w",
                    ) as f:
                        await f.write(html_output)

            if "/api/v1/policy/network-access/identity-stores" in api:
                async with aiofiles.open(
                    "Network Access Identity Stores/HTML/Network Access Identity Stores.html",
                    mode="w",
                ) as f:
                    await f.write(html_output)

            if "/api/v1/policy/network-access/policy-set" in api:
                async with aiofiles.open(
                    "Network Access Policy Sets/HTML/Network Access Policy Sets.html",
                    mode="w",
                ) as f:
                    await f.write(html_output)

            if "/api/v1/policy/network-access/security-groups" in api:
                async with aiofiles.open(
                    "Network Access Security Groups/HTML/Network Access Security Groups.html",
                    mode="w",
                ) as f:
                    await f.write(html_output)

            if "/api/v1/policy/network-access/service-names" in api:
                async with aiofiles.open(
                    "Network Access Service Names/HTML/Network Access Service Names.html",
                    mode="w",
                ) as f:
                    await f.write(html_output)

            if "/admin/API/mnt/Session/ActiveCount" in api:
                async with aiofiles.open(
                    "Active Sessions/HTML/Active Sessions.html", mode="w"
                ) as f:
                    await f.write(html_output)

            if "/admin/API/mnt/Session/PostureCount" in api:
                async with aiofiles.open(
                    "Posture Count/HTML/Posture Count.html", mode="w"
                ) as f:
                    await f.write(html_output)

            if "/admin/API/mnt/Session/ProfilerCount" in api:
                async with aiofiles.open(
                    "Profiler Count/HTML/Profiler Count.html", mode="w"
                ) as f:
                    await f.write(html_output)

            if "/admin/API/mnt/Version" in api:
                async with aiofiles.open("Version/HTML/Version.html", mode="w") as f:
                    await f.write(html_output)

            if "/admin/API/mnt/FailureReasons" in api:
                async with aiofiles.open(
                    "Failure Reasons/HTML/Failure Reasons.html", mode="w"
                ) as f:
                    await f.write(html_output)

    async def mindmap_file(self, parsed_json):
        template_dir = Path(__file__).resolve().parent
        env = Environment(loader=FileSystemLoader(str(template_dir)), enable_async=True)
        mindmap_template = env.get_template("ise_mindmap.j2")
        for api, payload in json.loads(parsed_json):
            mindmap_output = await mindmap_template.render_async(
                api=api, data_to_template=payload
            )
            if "/ers/config/allowedprotocols" in api:
                async with aiofiles.open(
                    "Allowed Protocols/Mindmap/Allowed Protocols.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

            if "/ers/config/adminuser" in api:
                async with aiofiles.open(
                    "Admin Users/Mindmap/Admin Users.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

            if "/ers/config/activedirectory" in api:
                async with aiofiles.open(
                    "Active Directory/Mindmap/Active Directory.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

            if "/ers/config/authorizationprofile" in api:
                async with aiofiles.open(
                    "Authorization Profiles/Mindmap/Authorization Profiles.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

            if "/ers/config/downloadableacl" in api:
                async with aiofiles.open("DACLs/Mindmap/DACLs.md", mode="w") as f:
                    await f.write(mindmap_output)

            if "/ers/config/endpoint" in api:
                if "/ers/config/endpointgroup" in api:
                    async with aiofiles.open(
                        "Endpoint Groups/Mindmap/Endpoint Groups.md", mode="w"
                    ) as f:
                        await f.write(mindmap_output)
                else:
                    async with aiofiles.open(
                        "Endpoints/Mindmap/Endpoints.md", mode="w"
                    ) as f:
                        await f.write(mindmap_output)

            if "/ers/config/identitygroup" in api:
                async with aiofiles.open(
                    "Identity Groups/Mindmap/Identity Groups.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

            if "/ers/config/idstoresequence" in api:
                async with aiofiles.open(
                    "Identity Store Sequences/Mindmap/Identity Store Sequences.md",
                    mode="w",
                ) as f:
                    await f.write(mindmap_output)

            if "/ers/config/internaluser" in api:
                async with aiofiles.open(
                    "Internal Users/Mindmap/Internal Users.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

            if "/ers/config/networkdevice" in api:
                if "/ers/config/networkdevicegroup" in api:
                    async with aiofiles.open(
                        "Network Device Groups/Mindmap/Network Device Groups.md",
                        mode="w",
                    ) as f:
                        await f.write(mindmap_output)
                else:
                    async with aiofiles.open(
                        "Network Devices/Mindmap/Network Devices.md", mode="w"
                    ) as f:
                        await f.write(mindmap_output)

            if "/ers/config/node" in api:
                async with aiofiles.open("Nodes/Mindmap/Nodes.md", mode="w") as f:
                    await f.write(mindmap_output)

            if "/ers/config/portal" in api:
                async with aiofiles.open("Portals/Mindmap/Portals.md", mode="w") as f:
                    await f.write(mindmap_output)

            if "/ers/config/profilerprofile" in api:
                async with aiofiles.open(
                    "Profilers/Mindmap/Profilers.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

            if "/ers/config/sgt" in api:
                async with aiofiles.open("SGTs/Mindmap/SGTs.md", mode="w") as f:
                    await f.write(mindmap_output)

            if "/ers/config/sgacl" in api:
                async with aiofiles.open("SGT ACLs/Mindmap/SGT ACLs.md", mode="w") as f:
                    await f.write(mindmap_output)

            if "/ers/config/selfregportal" in api:
                async with aiofiles.open(
                    "Self Registration Portals/Mindmap/Self Registration Portals.md",
                    mode="w",
                ) as f:
                    await f.write(mindmap_output)

            if "/ers/config/sponsorgroup" in api:
                async with aiofiles.open(
                    "Sponsor Groups/Mindmap/Sponsor Groups.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

            if "/ers/config/sponsorportal" in api:
                async with aiofiles.open(
                    "Sponsor Portals/Mindmap/Sponsor Portals.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

            if "/ers/config/sponsoredguestportal" in api:
                async with aiofiles.open(
                    "Sponsored Guest Portals/Mindmap/Sponsored Guest Portals.md",
                    mode="w",
                ) as f:
                    await f.write(mindmap_output)

            if "/api/v1/backup-restore/config/last-backup-status" in api:
                async with aiofiles.open(
                    "Last Backup/Mindmap/Last Backup.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

            if "/api/v1/certs/certificate-signing-request" in api:
                async with aiofiles.open("CSRs/Mindmap/CSRs.md", mode="w") as f:
                    await f.write(mindmap_output)

            if "/api/v1/certs/system-certificate" in api:
                async with aiofiles.open(
                    "System Certificates/Mindmap/System Certificates.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

            if "/api/v1/certs/trusted-certificate" in api:
                async with aiofiles.open(
                    "Trusted Certificates/Mindmap/Trusted Certificates.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

            if "/api/v1/deployment/node" in api:
                async with aiofiles.open(
                    "Deployment Nodes/Mindmap/Deployment Nodes.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

            if "/api/v1/deployment/pan-ha" in api:
                async with aiofiles.open("PAN HA/Mindmap/PAN HA.md", mode="w") as f:
                    await f.write(mindmap_output)

            if f"/api/v1/node/{ self.no_https_url }/interface" in api:
                async with aiofiles.open(
                    "Node Interfaces/Mindmap/Node Interfaces.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

            if f"/api/v1/profile/{ self.no_https_url }" in api:
                async with aiofiles.open(
                    "Node Profiles/Mindmap/Node Profiles.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

            if "/api/v1/license/system/connection-type" in api:
                async with aiofiles.open(
                    "License Connection Type/Mindmap/License Connection Type.md",
                    mode="w",
                ) as f:
                    await f.write(mindmap_output)

            if "/api/v1/license/system/eval-license" in api:
                async with aiofiles.open(
                    "Eval Licenses/Mindmap/Eval Licenses.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

            if "/api/v1/license/system/feature-to-tier-mapping" in api:
                async with aiofiles.open(
                    "License Feature Map/Mindmap/License Feature Map.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

            if "/api/v1/license/system/register" in api:
                async with aiofiles.open(
                    "License Register/Mindmap/License Register.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

            if "/api/v1/license/system/smart-state" in api:
                async with aiofiles.open(
                    "License Smart State/Mindmap/License Smart State.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

            if "/api/v1/license/system/tier-state" in api:
                async with aiofiles.open(
                    "License Tier State/Mindmap/License Tier State.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

            if "/api/v1/patch" in api:
                async with aiofiles.open("Patches/Mindmap/Patches.md", mode="w") as f:
                    await f.write(mindmap_output)

            if "/api/v1/hotpatch" in api:
                async with aiofiles.open(
                    "Hot Patches/Mindmap/Hot Patches.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

            if "/api/v1/repository" in api:
                async with aiofiles.open(
                    "Repositories/Mindmap/Repositories.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

            if "/api/v1/system-settings/proxy" in api:
                async with aiofiles.open("Proxies/Mindmap/Proxies.md", mode="w") as f:
                    await f.write(mindmap_output)

            if "/api/v1/system-settings/telemetry/transport-gateway" in api:
                async with aiofiles.open(
                    "Transport Gateways/Mindmap/Transport Gateways.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

            if "/api/v1/trustsec/sgacl/nbarapp/" in api:
                async with aiofiles.open(
                    "NBAR Apps/Mindmap/NBAR Apps.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

            if "/api/v1/policy/device-admin/command-sets" in api:
                async with aiofiles.open(
                    "Command Sets/Mindmap/Command Sets.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

            if "/api/v1/policy/device-admin/condition" in api:
                async with aiofiles.open(
                    "Conditions/Mindmap/Conditions.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

            if "/api/v1/policy/device-admin/dictionaries/authentication" in api:
                async with aiofiles.open(
                    "Authentication Dictionaries/Mindmap/Authentication Dictionaries.md",
                    mode="w",
                ) as f:
                    await f.write(mindmap_output)

            if "/api/v1/policy/device-admin/dictionaries/authorization" in api:
                async with aiofiles.open(
                    "Authorization Dictionaries/Mindmap/Authorization Dictionaries.md",
                    mode="w",
                ) as f:
                    await f.write(mindmap_output)

            if "/api/v1/policy/device-admin/dictionaries/policyset" in api:
                async with aiofiles.open(
                    "Policy Set Dictionary/Mindmap/Policy Set Dictionary.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

            if "/api/v1/policy/device-admin/identity-stores" in api:
                async with aiofiles.open(
                    "Identity Stores/Mindmap/Identity Stores.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

            if "/api/v1/policy/device-admin/policy-set" in api:
                async with aiofiles.open(
                    "Policy Sets/Mindmap/Policy Sets.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

            if "/api/v1/policy/device-admin/service-names" in api:
                async with aiofiles.open(
                    "Service Names/Mindmap/Service Names.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

            if "/api/v1/policy/device-admin/shell-profiles" in api:
                async with aiofiles.open(
                    "Shell Profiles/Mindmap/Shell Profiles.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

            if "/api/v1/policy/network-access/authorization-profiles" in api:
                async with aiofiles.open(
                    "Network Authorization Profiles/Mindmap/Network Authorization Profiles.md",
                    mode="w",
                ) as f:
                    await f.write(mindmap_output)

            if "/api/v1/policy/network-access/condition" in api:
                if "/api/v1/policy/network-access/condition/authentication" in api:
                    async with aiofiles.open(
                        "Network Access Condition Authentication/Mindmap/Network Access Condition Authentication.md",
                        mode="w",
                    ) as f:
                        await f.write(mindmap_output)

                elif "/api/v1/policy/network-access/condition/authorization" in api:
                    async with aiofiles.open(
                        "Network Access Condition Authorization/Mindmap/Network Access Condition Authorization.md",
                        mode="w",
                    ) as f:
                        await f.write(mindmap_output)

                elif "/api/v1/policy/network-access/condition/policyset" in api:
                    async with aiofiles.open(
                        "Network Access Condition Policy Sets/Mindmap/Network Access Condition Policy Sets.md",
                        mode="w",
                    ) as f:
                        await f.write(mindmap_output)
                else:
                    async with aiofiles.open(
                        "Network Access Conditions/Mindmap/Network Access Conditions.md",
                        mode="w",
                    ) as f:
                        await f.write(mindmap_output)

            if "/api/v1/policy/network-access/dictionaries" in api:
                if "/api/v1/policy/network-access/dictionaries/authentication" in api:
                    async with aiofiles.open(
                        "Network Access Dictionary Authentication/Mindmap/Network Access Dictionary Authentication.md",
                        mode="w",
                    ) as f:
                        await f.write(mindmap_output)

                elif "/api/v1/policy/network-access/dictionaries/authorization" in api:
                    async with aiofiles.open(
                        "Network Access Dictionary Authorization/Mindmap/Network Access Dictionary Authorization.md",
                        mode="w",
                    ) as f:
                        await f.write(mindmap_output)

                elif "/api/v1/policy/network-access/dictionaries/policyset" in api:
                    async with aiofiles.open(
                        "Network Access Dictionary Policy Sets/Mindmap/Network Access Dictionary Policy Sets.md",
                        mode="w",
                    ) as f:
                        await f.write(mindmap_output)

                else:
                    async with aiofiles.open(
                        "Network Access Dictionaries/Mindmap/Network Access Dictionaries.md",
                        mode="w",
                    ) as f:
                        await f.write(mindmap_output)

            if "/api/v1/policy/network-access/identity-stores" in api:
                async with aiofiles.open(
                    "Network Access Identity Stores/Mindmap/Network Access Identity Stores.md",
                    mode="w",
                ) as f:
                    await f.write(mindmap_output)

            if "/api/v1/policy/network-access/policy-set" in api:
                async with aiofiles.open(
                    "Network Access Policy Sets/Mindmap/Network Access Policy Sets.md",
                    mode="w",
                ) as f:
                    await f.write(mindmap_output)

            if "/api/v1/policy/network-access/security-groups" in api:
                async with aiofiles.open(
                    "Network Access Security Groups/Mindmap/Network Access Security Groups.md",
                    mode="w",
                ) as f:
                    await f.write(mindmap_output)

            if "/api/v1/policy/network-access/service-names" in api:
                async with aiofiles.open(
                    "Network Access Service Names/Mindmap/Network Access Service Names.md",
                    mode="w",
                ) as f:
                    await f.write(mindmap_output)

            if "/admin/API/mnt/Session/ActiveCount" in api:
                async with aiofiles.open(
                    "Active Sessions/Mindmap/Active Sessions.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

            if "/admin/API/mnt/Session/PostureCount" in api:
                async with aiofiles.open(
                    "Posture Count/Mindmap/Posture Count.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

            if "/admin/API/mnt/Session/ProfilerCount" in api:
                async with aiofiles.open(
                    "Profiler Count/Mindmap/Profiler Count.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

            if "/admin/API/mnt/Session/ActiveCount" in api:
                async with aiofiles.open("Version/Mindmap/Version.md", mode="w") as f:
                    await f.write(mindmap_output)

            if "/admin/API/mnt/Session/FailureReasons" in api:
                async with aiofiles.open(
                    "Failure Reasons/Mindmap/Failure Reasons.md", mode="w"
                ) as f:
                    await f.write(mindmap_output)

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
