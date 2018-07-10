"""
Automate the process of adding/deleting IP address through NetBox API.
"""

import requests


class NetBoxAPI(object):
    """API object to interact with NetBox API."""

    def __init__(self, host='netbox.example.com',
                 token='abcxyz123456',
                 verify=True):
        """Initialize API object.

        :param host: (str) IP address or domain of NetBox
        :param token: (str) API token used to authorize requests
        :param verify: (bool) verify SSL certificate
        """

        self.host = host
        self.token = token
        self.verify = verify
        self.headers = {'Authorization': 'Token {}'.format(self.token)}

    def get_prefix_id(self, prefix, limit=500, offset=0):
        """Get id of a prefix.

        :param prefix: (str) the prefix that we want to get corresponding id
        :param limit: (int) the number of entries to get from each query
        :param offset: (int) the position from which to start querying data
        :return: (int) id of the given prefix
        """

        url = "https://{}/api/ipam/prefixes/?limit={}&offset={}".format(self.host, limit, offset)
        try:
            rsp = requests.get(url, verify=self.verify)
        except Exception as exc:
            raise ValueError from exc
        else:
            if rsp.status_code != 200:
                msg = "Server replied with status code {}.".format(rsp.status_code)
                raise ValueError(msg)
            prefixes = rsp.json()
            while True:
                for pref in prefixes['results']:
                    if pref['prefix'] == prefix:
                        return pref['id']
                if prefixes['next'] is None:
                    return None
                prefixes = requests.get(prefixes['next']).json()

    def get_ip_id(self, ip_addr, limit=500, offset=0):
        """Get id of an IP address.

        :param ip_addr: (str) the IP address that we want to get corresponding id
        :param limit: (int) the number of entries to get from each query
        :param offset: (int) the position from which to start querying data
        :return: (int) id of the given IP
        """

        url = "https://{}/api/ipam/ip-addresses/?limit={}&offset={}".format(self.host, limit, offset)
        try:
            rsp = requests.get(url, verify=self.verify)
        except Exception as exc:
            raise ValueError from exc
        else:
            if rsp.status_code != 200:
                msg = "Server replied with status code {}.".format(rsp.status_code)
                raise ValueError(msg)
            ips = rsp.json()
            while True:
                for ip in ips['results']:
                    if ip['address'] == ip_addr:
                        return ip['id']
                if ips['next'] is None:
                    return None
                ips = requests.get(ips['next']).json()

    def get_available_ips(self, prefix):
        """Get available IPs from a prefix.

        :param prefix: (str) the prefix to get available IPs from
        :return: (list) a list containing available IPs
        """

        length = int(prefix.split('/')[1])
        num_ips = 2 ** (32 - length)  # the number of IPs in subnet
        prefix_id = self.get_prefix_id(prefix)
        url = "https://{}/api/ipam/prefixes/{}/available-ips/?limit={}".format(self.host, prefix_id, num_ips)
        try:
            rsp = requests.get(url, verify=self.verify)
        except Exception as exc:
            raise ValueError from exc
        else:
            if rsp.status_code != 200:
                msg = "Server replied with status code {}.".format(rsp.status_code)
                raise ValueError(msg)
            return rsp.json()

    @staticmethod
    def _get_reserved_ips(prefix, num_reserved_ips):
        """Get reserved IPs from a prefix.

        :param prefix: (str) the prefix from which to get reserved IPs
        :param num_reserved_ips: (int) the number of reserved (non-assigned) IPs in this prefix
        :return: (list) a list containing reserved IPs
        """

        address, length = prefix.split('/')
        first_octet, second_octet, third_octet, fourth_octet = address.split('.')
        third_octet = int(third_octet)
        fourth_octet = int(fourth_octet)
        length = int(length)
        num_ips = 2 ** (32 - length)  # the number of IPs in subnet
        if num_reserved_ips > num_ips:
            num_reserved_ips = num_ips
        reserved_ips = []
        count = 0
        while third_octet <= 255:
            while fourth_octet <= 255:
                ip = '{}.{}.{}.{}/{}'.format(first_octet, second_octet, third_octet, fourth_octet, length)
                reserved_ips.append(ip)
                count += 1
                if count == num_reserved_ips:
                    return reserved_ips
                fourth_octet += 1
            third_octet += 1
            fourth_octet = 0

    def post_ip_to_netbox(self, **kwargs):
        """Post an allocated IP to NetBox.

        :param kwargs: (dict) attribute-value pairs
        :return: (bool) True if posted successfully
        """

        data = {attr: val for attr, val in kwargs.items()}
        url = "https://{}/api/ipam/ip-addresses/".format(self.host)
        try:
            rsp = requests.post(url, headers=self.headers, json=data, verify=self.verify)
        except Exception as exc:
            raise ValueError from exc
        else:
            if rsp.status_code != 201:
                msg = "Server replied with status code {}.".format(rsp.status_code)
                raise ValueError(msg)
            return True

    def update_ip_on_netbox(self, ip_addr, **kwargs):
        """Update attributes of an allocated IP on NetBox.

        :param ip_addr: (str) the IP address that we want to update attributes
        :param kwargs: (dict) attribute-value pairs
        :return: (bool) True if updated successfully
        """

        data = {attr: val for attr, val in kwargs.items()}
        data['address'] = ip_addr
        ip_id = self.get_ip_id(ip_addr)
        url = "https://{}/api/ipam/ip-addresses/{}/".format(self.host, ip_id)
        try:
            rsp = requests.patch(url, headers=self.headers, json=data, verify=self.verify)
        except Exception as exc:
            raise ValueError from exc
        else:
            if rsp.status_code != 200:
                msg = "Server replied with status code {}.".format(rsp.status_code)
                raise ValueError(msg)
            return True

    def delete_ip_from_netbox(self, ip_addr):
        """Delete an IP from NetBox.

        :param ip_addr: (int) the IP address that we want to delete
        :return: (bool) True if deleted successfully
        """

        ip_id = self.get_ip_id(ip_addr)
        url = "https://{}/api/ipam/ip-addresses/{}/".format(self.host, ip_id)
        try:
            rsp = requests.delete(url, headers=self.headers, verify=self.verify)
        except Exception as exc:
            raise ValueError from exc
        else:
            if rsp.status_code != 204:
                msg = "Server replied with status code {}.".format(rsp.status_code)
                raise ValueError(msg)
            return True

    def allocate_ip_to(self, description, prefix='192.168.1.0/24', num_reserved_ips=20, post_to_netbox=True):
        """Allocate an IP from available IPs.

        :param prefix: (str) the prefix from which to allocate an available IP
        :param description: (str) description for allocated IP
        :param num_reserved_ips: (int) the number of reserved (non-assigned) IPs in this prefix
        :param post_to_netbox: (bool) whether or not to post the allocated IP to NetBox
        :return: (str) an available IP
        """

        available_ips = self.get_available_ips(prefix)
        if num_reserved_ips > 0:
            reserved_ips = NetBoxAPI._get_reserved_ips(prefix, num_reserved_ips)
            for ip in available_ips:
                if ip['address'] not in reserved_ips:
                    if post_to_netbox:
                        self.post_ip_to_netbox(description=description, address=ip['address'])
                    return ip['address']
            return None
        
        if post_to_netbox:
            self.post_ip_to_netbox(description=description, address=available_ips[0]['address'])
        return available_ips[0]['address']
