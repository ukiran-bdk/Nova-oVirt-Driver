# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright (c) 2013 Hewlett-Packard Development Company, L.P.
# Copyright 2011 OpenStack LLC.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Class for VM tasks like spawn, snapshot, suspend, resume etc.
"""

import base64
import os
import time
import urllib
import urllib2
import uuid

import psycopg2
import paramiko
import ConfigParser

from oslo.config import cfg

from nova import block_device
from nova.compute import api as compute
from nova.compute import power_state
from nova.compute import vm_states
from nova.compute import task_states
#from nova.compute import instance_types
from nova import context as nova_context
from nova.openstack.common import excutils
from nova.openstack.common import importutils
from nova.openstack.common import log as logging
from nova.openstack.common import timeutils
from nova.virt import driver
from nova import db
from nova import utils
from nova.openstack.common.gettextutils import _

# import ovirtsdk
from ovirtsdk.xml import params
from ovirtsdk.infrastructure.brokers import Templates
from ovirtsdk.xml.params import Template
import openstack_utils as stackutils


LOG = logging.getLogger(__name__)

RHEVM_POWER_STATES = {
    'up': power_state.RUNNING,
    'down': power_state.SHUTDOWN,
    'powering_up': power_state.BUILDING,
    'powering_down':   power_state.SHUTDOWN,
    'suspended': power_state.SUSPENDED,
    'saving_state':  power_state.SUSPENDED,
    'unassigned': power_state.NOSTATE,
    'paused': power_state.PAUSED,
    'migrating_to': power_state.BUILDING,
    'unknown': power_state.NOSTATE,
    'wait_for_launch': power_state.BUILDING,
    'reboot_in_progress': power_state.BUILDING,
    'restoring_state': power_state.BUILDING,
    'image_locked': power_state.BUILDING

}


class oVirtOps(object):

    """Management class for VM-related tasks."""

    def __init__(self, session):
        """Initializer."""
        #self.compute_api = compute.API()
        self._session = session
        #self._virtapi = virtapi

    def list_instances(self):
        """Lists the VM instances that are registered with the Rhevm/oVirt."""
        instances = self._session.vms.list()
        instance_names = []
        for instance in instances:
            instance_names.append(instance.name)
        return instance_names

    def get_info(self, instance_name):
        """Return data about the VM instance."""
        LOG.debug("**** get_instance_info ******")
        instance = self._session.vms.get(instance_name)
        if instance is None:
            return {
                'state': RHEVM_POWER_STATES['unknown'],
                'max_mem': 0,
                'mem': 0,
                'num_cpu': 0,
                'cpu_time': 0}
        else:
            power_state = RHEVM_POWER_STATES[instance.status.state]
            # memory = (instance.memory)/(1024*1024)  # in MB
            memory = (instance.memory) / 1024  # in KB
            cpu_num = instance.cpu.topology.cores

        return {'state': power_state,
                'max_mem': memory,
                'mem': memory,
                'num_cpu': cpu_num,
                'cpu_time': 0}

    def spawnBackUp(self, context, instance, image_meta, network_info,
              block_device_info=None):
        """
        Creates a VM instance.

        Steps followed are:

        1. Create a VM with no disk and the specifics in the instance object
           like RAM size.
        2. For flat disk
          2.1. Create a dummy vmdk of the size of the disk file that is to be
               uploaded. This is required just to create the metadata file.
          2.2. Delete the -flat.vmdk file created in the above step and retain
               the metadata .vmdk file.
          2.3. Upload the disk file.
        3. For sparse disk
          3.1. Upload the disk file to a -sparse.vmdk file.
          3.2. Copy/Clone the -sparse.vmdk file to a thin vmdk.
          3.3. Delete the -sparse.vmdk file.
        4. Attach the disk to the VM by reconfiguring the same.
        5. Power on the VM.
        """
        LOG.debug(_("---------------vmops spawn method---------------------- "))
        try:
            instance_name = instance['name']
            instance_id = instance['id']
            instance_node = instance['node']
            LOG.debug("Instance is provisioned on cluster ---> %s " %
                      instance_node)
            instance_memory = instance['memory_mb']
            instance_vcpus = instance['vcpus']
            instance_root_gb = instance['root_gb']
            image_name = image_meta['name']
            LOG.debug("Instance is provisioned with template ---> %s " % image_name)
            
            LOG.debug(_("---------------vmops spawn network_info---------------------- "))
            LOG.debug(_(" network_info--------->>>>  %s" %network_info))
            LOG.debug(_(" type of network_info--------->>>>  %s" %type(network_info)))
            
            try:
                for (network, info_dict) in network_info:
                    mac_add = info_dict['mac']
                    network_name = info_dict['label']
                    ips = info_dict['ips']
                    for ip in ips:
                        instance_ip = ip['ip']
                        netmask = ip['netmask']
                        gateway = ip['gateway']
            except Exception as e:
                LOG.debug(" network_info error %s " % str(e))

            MB = 1024 * 1024
            GB = 1024 * MB
            
            LOG.debug(_("---------------vmops spawn parameters---------------------- "))
            LOG.debug(_(" instance_name--------->>>>  %s" %instance['name']))
            LOG.debug(_(" instance_id--------->>>>  %s" %instance['id']))
            LOG.debug(_(" instance_node--------->>>>  %s" %instance['node']))
            LOG.debug(_(" instance_memory--------->>>>  %s" %instance['memory_mb']))
            LOG.debug(_(" instance_vcpus--------->>>>  %s" %instance['vcpus']))
            LOG.debug(_(" instance_root_gb--------->>>>  %s" %instance['root_gb']))
            LOG.debug(_(" image_name--------->>>>  %s" %image_meta['name']))
            
            cluster_name = self._session.clusters.get(instance_node)
            
            LOG.debug(_("---------------vmops spawn parameters Template---------------------- "))
            template_name = self._session.templates.get(image_name)
            
            if template_name is None:
                LOG.debug(_("---------------vmops spawn Template is None---------------------- "))
                raise Exception(" Template doesn't exists ")

            template_cpus = template_name.cpu.topology.cores
            template_disks = template_name.disks
            template_disk1 = template_disks.get(name="Disk 1")
            template_disk1_size = (template_disk1.get_size()) / GB
            template_disk2_size = (instance_root_gb - template_disk1_size)

            vm_memory_mb = instance_memory * MB
            vm_cpu_cores = (instance_vcpus - template_cpus) + 1

            vcpu = params.CPU(topology=params.CpuTopology(
                cores=vm_cpu_cores, sockets=1))
            param = params.VM(name=instance_name, cluster=cluster_name,
                              template=template_name,
                              memory=vm_memory_mb, cpu=vcpu)

            instance = self._session.vms.add(param)

            instance.nics.add(params.NIC(name='nic', network=params.Network(
                name=network_name), mac=params.MAC(address=mac_add),
                interface='Red Hat VirtIO'))

            while self._session.vms.get(instance_name).status.state != 'down':
                time.sleep(2)

            storagedomains = self._session.storagedomains.list()
            for storage in storagedomains:
                if storage.type_ == 'data' and storage.get_master():
                    storage_name = storage.name

            if template_disk2_size > 0:
                instance.disks.add(params.Disk(storage_domains=
                                               params.StorageDomains(
                                               storage_domain=[self._session.
                                               storagedomains.get(
                                               name=storage_name)]),
                                               size=template_disk2_size * GB,
                                               type_='data',
                                               interface='VirtIO',
                                               format='cow'))

            while self._session.vms.get(instance_name).status.state != 'down':
                time.sleep(3)

            try:
                instance.start()
            except Exception as e:
                LOG.debug(" VM is not able to start %s " % str(e))
                instance.delete()
                raise

            while self._session.vms.get(instance_name).status.state != 'up':
                time.sleep(3)

            if template_disk2_size > 0:
                self.attach_disk(instance_ip, template_disk2_size)

            LOG.audit("A new instance:--> %s is being successfully provisioned"
                      % instance_name)
        except Exception as e:
            LOG.audit("== Instance provisioning failed ==== %s" % str(e))
            raise Exception
    
    def spawn(self, context, instance, image_meta, network_info,block_device_info=None):
        LOG.debug(_("---------------vmops spawn method---------------------- "))
        
        try:
            '''
            LOG.debug(_("---------------vmops spawn parameters---------------------- "))
            LOG.debug(_(" instance_name--------->>>>  %s" %instance['name']))
            LOG.debug(_(" instance_id--------->>>>  %s" %instance['id']))
            LOG.debug(_(" instance_node--------->>>>  %s" %instance['node']))
            LOG.debug(_(" instance_memory--------->>>>  %s" %instance['memory_mb']))
            LOG.debug(_(" instance_vcpus--------->>>>  %s" %instance['vcpus']))
            LOG.debug(_(" instance_root_gb--------->>>>  %s" %instance['root_gb']))
            LOG.debug(_(" image_name--------->>>>  %s" %image_meta['name']))
            LOG.debug(_(" image_id--------->>>>  %s" %image_meta['id']))
            LOG.debug(_("Type of image_id---------->>>>  %s" %type(image_meta['id'])))
            
            LOG.debug(_("Type of context---------->>>>  %s" %type(context)))
            LOG.debug(_("Type of instance---------->>>>  %s" %type(instance)))
            for key in instance.keys():
                LOG.debug(_("Key, Value ---------->>>>  %s : %s" %(key,instance[key])))
            LOG.debug(_("Type of image_meta---------->>>>  %s" %type(image_meta)))
            for key in image_meta.keys():
                LOG.debug(_("Key, Value ---------->>>>  %s : %s" %(key,image_meta[key])))
            '''    
            LOG.debug(_("Type of block_device_info---------->>>>  %s" %type(block_device_info)))
            LOG.debug(_("Type of network_info---------->>>>  %s" %type(network_info)))
            LOG.debug(_("---------------network_info details---------------------- "))
                  
            
            try:
                for i in network_info:
                    LOG.debug(_("Type of i ---------->>>>  %s" %type(i)))
                    LOG.debug(_("mac_address ---------->>>>  %s" %i['address']))
                    LOG.debug(_("network_name ---------->>>>  %s" %i['network']['bridge']))
                    
                    port_id = i['ovs_interfaceid']
                    mac = i['address']
                    
                    LOG.debug(_("id ---------->>>>  %s" %i['id']))
                    LOG.debug(_("address ---------->>>>  %s" %i['address']))
                    LOG.debug(_("network ---------->>>>  %s" %i['network']))
                    LOG.debug(_("type ---------->>>>  %s" %i['type']))
                    LOG.debug(_("devname ---------->>>>  %s" %i['devname']))
                    LOG.debug(_("ovs_interfaceid ---------->>>>  %s" %i['ovs_interfaceid']))
                    
                    LOG.debug(_("qbh_params ---------->>>>  %s" %i['qbh_params']))
                    LOG.debug(_("qbg_params ---------->>>>  %s" %i['qbg_params']))
                    
                    LOG.debug(_("fixed_ips ---------->>>>  %s" %i.fixed_ips()))
                    LOG.debug(_("floating_ips ---------->>>>  %s" %i.floating_ips()))
                    LOG.debug(_("labeled_ips ---------->>>>  %s" %i.labeled_ips()))
                    
                    for key in i.keys():
                        LOG.debug(_("Key, Value ---------->>>>  %s : %s" %(key,i[key])))
                    
            except Exception as e:
                #LOG.debug(" network_info error %s " % str(e))
                LOG.debug(_("network_info error %s" %str(e) ))
            
            #data = network_info['data']
            #target_lun = data['target_lun']
            #target_iqn = data['target_iqn']
            #target_portal = data['target_portal']
            
            #LOG.debug(_(" target_lun--------->>>>  %s" %target_lun))
            #LOG.debug(_(" target_iqn--------->>>>  %s" %target_iqn))
            #LOG.debug(_(" target_portal--------->>>>  %s" %target_portal))
            
            MB = 1024 * 1024
            GB = 1024 * MB
            
            #name = instance['name']
            name = instance['display_name'] 
            memory = instance['memory_mb'] * MB 
            cluster = self._session.clusters.get(instance['node'])
            tdesc =  image_meta['name'] + " ("+str(image_meta['id'])[0:7]+")"
            
            template = self._session.templates.get('Blank') 
            for t in self._session.templates.list():
                LOG.debug(_("tdesc, t.get_description() ---------->>>>  %s : %s" %(tdesc,t.get_description())))
                if( tdesc == t.get_description()):
                    template = t
             
            #template = self._session.templates.get('GlanceTemplate-2897d1c') 
            vmType = 'server' 
            
            #instance_vcpus = instance['vcpus']
            #template_cpus = template.cpu.topology.cores
            #vm_cpu_cores = (instance_vcpus - template_cpus) + 1
            cpuTopology = params.CpuTopology(cores=2, sockets=1) 
            cpu = params.CPU(topology=cpuTopology) 
            
            ovirtVMParam = params.VM(name=name, 
                                 type_=vmType, 
                                 memory=memory, 
                                 cluster=cluster, 
                                 cpu=cpu, 
                                 template=template) 
             
            newVm = self._session.vms.add(ovirtVMParam)
            LOG.debug(_("---------------vmops spawn - Added New VM---------------------- "))
            
            LOG.debug(_("---------------vmops spawn - Delete port---------------------- "))
            
            
            #stackutils.delete_port(port_id)
                        
            LOG.debug(_("---------------vmops spawn - Add port---------------------- "))
                        
            nicName = 'nic-1' 
            macparam = params.MAC(address=mac) 
            network = self._session.networks.get(name='Net1') # ovirtmgmt
            nicInterface = 'virtio' 
            nic = params.NIC(name=nicName, 
                             interface=nicInterface, 
                             #mac=macparam, 
                             network=network) 
            
            newNic = newVm.nics.add(nic) 
            LOG.debug(_("---------------vmops spawn - Added New NIC---------------------- "))
            
            '''
            storage = api.storagedomains.get(name='DataNFS') 
            storageDomain = params.StorageDomains(storage_domain=[storage]) 
            size = 1 * pow(2, 30) 
            diskType = 'system' 
            diskFormat = 'cow' 
            diskInterface = 'virtio' 
            sparse = True 
            bootable = True 
            
            disk = params.Disk(storage_domains=storageDomain, 
                               size=size, 
                               type_=diskType, 
                               interface=diskInterface, 
                               format=diskFormat, 
                               sparse=sparse, 
                               bootable=bootable) 
            
            ovirtDisk = newVm.disks.add(disk)
            print "Added Disk"
            '''
            LOG.debug(_("---------------vmops spawn - waiting to status DOWN....---------------------- "))
            while self._session.vms.get(name).status.state != 'down':
                time.sleep(3)
            LOG.debug(_("---------------vmops spawn - Ready to Start---------------------- "))
            
            LOG.debug(_("---------------vmops spawn - Starting New VM---------------------- "))
            try:
                newVm.start()
            except Exception as e:
                #print " ERROR....VM is not able to start : ", str(e)
                LOG.debug(_("---------------vmops spawn - ERROR....VM is not able to start :---------------------- "))
                newVm.delete()
                raise Exception

            while self._session.vms.get(name).status.state != 'up':
                time.sleep(3)

            LOG.audit("A new instance:--> %s is being successfully provisioned" % name)
        except Exception as e:
            LOG.audit("== Instance provisioning failed ==== %s" % str(e))
            raise Exception

    def attach_disk(self, instance, volume):
        LOG.info(_("*******rhevm -vmops ---- attach_disk--instance-->>%s" %instance))
        LOG.info(_("*******rhevm -vmops ---- attach_disk--volume-->>%s" %volume))
        try:
            vm = self._session.vms.get(name=instance)
            disk = self._session.disks.get(volume)
            o = vm.disks.add(disk)
            o.activate()
            #pass
        except Exception as e:
               LOG.debug(_("disk attach error %s" %str(e) ))
    
    def detach_disk(self, instance, volume):
        LOG.info(_("*******rhevm -vmops ---- detach_disk--instance-->>%s" %instance))
        LOG.info(_("*******rhevm -vmops ---- detach_disk--volume-->>%s" %volume))
        try:
            vm = self._session.vms.get(name=instance)
            disk = vm.disks.get(name=volume)
            detach = params.Action(detach=True)
            disk.delete(action=detach)
        except Exception as e:
            LOG.debug(_("disk detach error %s" %str(e) ))

    def attach_disk_old(self, instance_ip, template_disk2_size):

        try:

            ip = str(instance_ip)
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username='root', password='iso*help')

            pvcreate = 'pvcreate /dev/vdb'
            stdin, stdout, stderr = ssh.exec_command("pvcreate /dev/vdb")
            # op=stdout.read()
            stdin, stdout, stderr = ssh.exec_command("vgdisplay")
            op = stdout.read()
            vg_name = op.split('\n')[1].split()[2]

            vgextend = 'vgextend ' + vg_name + ' /dev/vdb'
            stdin, stdout, stderr = ssh.exec_command(vgextend)
            # op=stdout.read()
            size = str(template_disk2_size - 0.5) + 'G'
            lvextend = 'lvextend -L+' + size + \
                ' /dev/' + vg_name + '/lv_root /dev/vdb'
            stdin, stdout, stderr = ssh.exec_command(lvextend)
            # op=stdout.read()
            resize = 'resize2fs /dev/mapper/' + vg_name + '-lv_root'
            stdin, stdout, stderr = ssh.exec_command(resize)
            # op=stdout.read()
            LOG.debug("Disk added successfully")
        except Exception as e:
            LOG.debug("Disk attach failed %s" % str(e))

    def reboot(self, instance, network_info):
        """Reboot a VM instance."""
        instance_name = instance['name']
        instance = self._session.vms.get(instance_name)
        LOG.debug(_("Rebooting Instance : %s") % instance_name)
        if instance is not None:
            if instance.status.state != 'down':
                instance.shutdown()
            while self._session.vms.get(instance_name).status.state != 'down':
                time.sleep(3)
            instance.start()
            while self._session.vms.get(instance_name).status.state != 'up':
                time.sleep(3)
        LOG.audit(_("Instance--->: %s is successfully rebooted") %
                  instance_name)

    def destroy(self, instance_name, network_info):
        """Delete a VM instance"""
        try:
            instance = self._session.vms.get(instance_name)
            if instance is not None:
                if instance.status.state != 'down':
                    instance.stop()
                while self._session.vms.get(instance_name).status.state \
                        != 'down':
                    time.sleep(3)
                instance.delete()
                time.sleep(5)
            LOG.audit(_("Instance--->: %s is successfully deleted ") %
                      instance_name)
        except Exception as e:
            LOG.audit(_("Instance doesn't exists ") % str(e))

    def suspend(self, instance_name):
        """Suspend the specified instance."""

        instance = self._session.vms.get(instance_name)
        LOG.debug(_("Suspending Instance : %s") % instance_name)
        if instance is not None:
            if instance.status.state != 'down':
                instance.suspend()
            while self._session.vms.get(instance_name).status.state \
                    != 'suspended':
                time.sleep(3)
        LOG.audit(_("Instance--->: %s is successfully suspended") %
                  instance_name)

    def resume(self, instance_name):
        """Resume the specified instance."""

        instance = self._session.vms.get(instance_name)
        LOG.debug(_("Resuming Instance : %s") % instance_name)
        if instance is not None:
            if instance.status.state == 'suspended':
                instance.start()
            while self._session.vms.get(instance_name).status.state \
                    != 'up':
                time.sleep(1)
        LOG.audit(_("Instance--->: %s is successfully resumed") %
                  instance_name)

    def power_off(self, instance_name):
        """stop the specified instance."""

        instance = self._session.vms.get(instance_name)
        LOG.debug(_("Stopping Instance : %s") % instance_name)
        if instance is not None:
            if instance.status.state != 'down':
                instance.stop()
            while self._session.vms.get(instance_name).status.state \
                    != 'down':
                time.sleep(1)
        LOG.audit(_("Instance--->: %s is successfully shutoff") %
                  instance_name)

    def power_on(self, instance_name):
        """start the specified instance."""

        instance = self._session.vms.get(instance_name)
        LOG.debug(_("Starting Instance : %s") % instance_name)
        if instance is not None:
            if instance.status.state == 'down':
                instance.start()
            while self._session.vms.get(instance_name).status.state \
                    != 'up':
                time.sleep(1)
        LOG.audit(_("Instance--->: %s is successfully started") %
                  instance_name)

    def pause(self,instance_name):
        msg = _("pause not supported for ovirtapi")
        raise NotImplementedError(msg)
       
    def unpause(self,instance_name):
        msg = _("pause not supported for ovirtapi")
        raise NotImplementedError(msg)
    
    