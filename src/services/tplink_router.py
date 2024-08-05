from tplinkrouterc6u import TplinkRouterProvider


class TPLinkRouter:
    def __init__(self, logging, password, router_host='http://192.168.0.1'):
        self.password = password
        self.logging = logging

    def get_ip_address(self):
        router = TplinkRouterProvider.get_client('http://192.168.0.1', self.password)

        try:
            router.authorize()
            ipv4_status = router.get_ipv4_status()
            # Get IP Address 73.63.43.75
            self.logging.info(f'retrieved wan ip address: {ipv4_status.wan_ipv4_ipaddress}')
            return str(ipv4_status.wan_ipv4_ipaddress)
        except Exception as e:
            self.logging.error('an error occurred retrieving the ip address: ', e)
        finally:
            router.logout()  # always logout as only 1 logged in user is allowed at a time

        return None
