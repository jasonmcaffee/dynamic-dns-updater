from cloudflare import Cloudflare
from dotenv import load_dotenv


class CloudflareUpdater:
    def __init__(self, logging, cloudflare_api_global_key, cloudflare_email):
        self.logging = logging
        self.cloudflare_api_global_key = cloudflare_api_global_key
        self.cloudflare_email = cloudflare_email

    def update_dns_records(self, new_ip, zone_and_record_names):

        # assume that the zone and record name are the same.
        # zone_and_record_names = [
        #     'jasonmcaffee.com',
        #     'yogajhana.com'
        # ]
        cloudflare_client = Cloudflare(api_key=self.cloudflare_api_global_key, api_email=self.cloudflare_email)

        for zone_and_record_name in zone_and_record_names:
            self.update_dns_record(cloudflare_client, zone_and_record_name, zone_and_record_name, new_ip)

    def update_dns_record(self, cf, zone_name, record_name, new_ip):
        try:
            self.logging.info(f'getting list of zones for zone_name: {zone_name}')
            zones = cf.zones.list(name=zone_name)
            if not zones:
                self.logging.error(f"❌ Zone {zone_name} not found. ❌")
                return
            zone_1 = zones.result[0]
            zone_id = zone_1.id
        except Exception as e:
            self.logging.error(f"❌ Failed to get zones: {e} ❌")
            return

        # Get the DNS record ID
        try:
            self.logging.info(f'getting dns records for zone and record name {record_name}')
            dns_records = cf.dns.records.list(zone_id=zone_id, name=record_name)
            if not dns_records:
                self.logging.error(f"❌ DNS record {record_name} not found. ❌")
                return
            record_1 = dns_records.result[0]
            if record_1.content == new_ip:
                self.logging.info(f'✅ Existing IP of {record_1.content} matches new_ip of {new_ip} ✅')
                return
            record_id = record_1.id
        except Exception as e:
            self.logging.error(f"❌ Failed to get DNS records: {e} ❌")
            return

        try:
            self.logging.info(f'updating dns record with ip: {new_ip}')
            cf.dns.records.update(zone_id=zone_id, content=new_ip, type='A', name=record_name, dns_record_id=record_id,
                                  proxied=True)
            self.logging.info("✅ DNS record updated successfully! ✅")
        except Exception as e:
            self.logging.error(f"❌ Failed to update DNS record: {e} ❌")
