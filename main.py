import time

from dotenv import load_dotenv
import logging
import os
import schedule
from src.services.cloudflare_updater import CloudflareUpdater
from src.services.tplink_router import TPLinkRouter


def main():
    load_dotenv()
    logging.basicConfig(force=True, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logging.info('starting dynamic dns updater...')

    # read env vars
    tplink_router_password = os.getenv('TP_LINK_ROUTER_PASSWORD')
    cloudflare_api_global_key = os.getenv('CLOUDFLARE_GLOBAL_KEY')  # this must be the global key, not a token!
    cloudflare_email = os.getenv('CLOUDFLARE_EMAIL')

    # create services
    cloudflare_updater = CloudflareUpdater(logging, cloudflare_api_global_key, cloudflare_email)
    tplink_router = TPLinkRouter(logging, tplink_router_password)

    # perform the update
    zone_and_record_names = [
        'jasonmcaffee.com',
        'yogajhana.com'
    ]

    def get_ip_address_and_perform_dns_update_if_needed():
        logging.info('performing dns record update, if needed...')
        new_ip = tplink_router.get_ip_address()
        if new_ip is None:
            logging.error('unable to update dns records due to no wan ip address found')
            return
        logging.info(f'setting new ip to {new_ip}...')
        cloudflare_updater.update_dns_records(new_ip, zone_and_record_names)

    get_ip_address_and_perform_dns_update_if_needed()

    schedule.every(5).minutes.do(get_ip_address_and_perform_dns_update_if_needed)

    while True:
        schedule.run_pending()
        time.sleep(1)


if __name__ == '__main__':
    main()
