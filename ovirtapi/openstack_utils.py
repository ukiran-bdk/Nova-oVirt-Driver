#!/usr/bin/env python
from neutronclient.v2_0 import client
import novaclient.v1_1.client as nvclient
import os

def get_credentials():
    d = {}
    '''
    d['username'] = os.environ['OS_USERNAME']
    d['password'] = os.environ['OS_PASSWORD']
    d['auth_url'] = os.environ['OS_AUTH_URL']
    d['tenant_name'] = os.environ['OS_TENANT_NAME']
    '''
    
    d['username'] = 'admin'
    d['password'] = 'secret'
    d['auth_url'] = 'http://127.0.0.1:5000/v2.0'
    d['tenant_name'] = 'admin'
    return d

def get_nova_credentials():
    d = {}
    '''
    d['username'] = os.environ['OS_USERNAME']
    d['api_key'] = os.environ['OS_PASSWORD']
    d['auth_url'] = os.environ['OS_AUTH_URL']
    d['project_id'] = os.environ['OS_TENANT_NAME']
    '''
    d['username'] = 'admin'
    d['api_key'] = 'secret'
    d['auth_url'] = 'http://127.0.0.1:5000/v2.0'
    d['project_id'] = 'admin'
    
    return d


def print_values(val, type):
    if type == 'ports':
        val_list = val['ports']
    if type == 'networks':
        val_list = val['networks']
    if type == 'routers':
        val_list = val['routers']
    for p in val_list:
        for k, v in p.items():
            print("%s : %s" % (k, v))
        print('\n')
 
 
def print_values_server(val, server_id, type):
    if type == 'ports':
        val_list = val['ports']
 
    if type == 'networks':
        val_list = val['networks']
    for p in val_list:
        bool = False
        for k, v in p.items():
            if k == 'device_id' and v == server_id:
                bool = True
        if bool:
            for k, v in p.items():
                print("%s : %s" % (k, v))
            print('\n')

def create_network(network_name):
    credentials = get_credentials()
    neutron = client.Client(**credentials)
    try:
            body_sample = {'network': {'name': network_name,'admin_state_up': True}}
            netw = neutron.create_network(body=body_sample)
            net_dict = netw['network']
            network_id = net_dict['id']
            print('Network %s created' % network_id)
            body_create_subnet = {'subnets': [{'cidr': '192.168.199.0/24','ip_version': 4, 'network_id': network_id}]}
            subnet = neutron.create_subnet(body=body_create_subnet)
            print('Created subnet %s' % subnet)
    finally:
            print("Execution completed")

def create_port(server_id,network_id,port_name):
    credentials = get_nova_credentials()
    nova_client = nvclient.Client(**credentials)
    server_detail = nova_client.servers.get(server_id)
    print(server_detail.id)
 
    if server_detail != None:
            credentials = get_credentials()
            neutron = client.Client(**credentials)
            body_value = {
                     "port": {
                             "admin_state_up": True,
                             "device_id": server_id,
                             "name": port_name,
                             "network_id": network_id
                      }
                 }
            response = neutron.create_port(body=body_value)
            print(response)

def print_server_details(server_id):
    credentials = get_nova_credentials()
    nova_client = nvclient.Client(**credentials)
    server_detail = nova_client.servers.get(server_id)
    print server_detail


def list_networks():
    credentials = get_credentials()
    neutron = client.Client(**credentials)
    netw = neutron.list_networks()
    print_values(netw, 'networks')


def list_ports():
    credentials = get_credentials()
    neutron = client.Client(**credentials)
    ports = neutron.list_ports()
    print_values(ports, 'ports')


def delete_port(port_id):
    credentials = get_credentials()
    neutron = client.Client(**credentials)
    neutron.delete_port(port_id)
    print 'Deleted port with ID: ',port_id

#print 'Hello'
#list_networks()
#print '---------------------'
#list_ports()
