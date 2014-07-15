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

    def spawn(self, context, instance, image_meta, network_info,block_device_info=None):
        """ Creates a VM instance in oVirt."""
        try:
            
            try:
                for i in network_info:
                    port_id = i['ovs_interfaceid']
                    mac = i['address']
            except Exception as e:
                LOG.debug(_("network_info error %s" %str(e)))
            
            MB = 1024 * 1024
            GB = 1024 * MB
            
            #name = instance['name']
            name = instance['display_name']
            cluster = self._session.clusters.get(instance['node'])
            
            
            memory = instance['memory_mb'] * MB 
            
            template = self._session.templates.get('Blank')
            
            tdesc =  image_meta['name'] + " ("+str(image_meta['id'])[0:7]+")"
            for t in self._session.templates.list():
                if( tdesc == t.get_description()):
                    template = t
             
            vmType = 'server' 
            
            instance_vcpus = instance['vcpus']
            template_cpus = template.cpu.topology.cores
            vm_cpu_cores = (instance_vcpus - template_cpus) + 1
            LOG.info(_("*******rhevm -vmops ---- spawn--vm_cpu_cores-->>%s" %vm_cpu_cores))
            
            cpuTopology = params.CpuTopology(cores=vm_cpu_cores, sockets=1) 
            cpu = params.CPU(topology=cpuTopology) 
            
            ovirtVMParam = params.VM(name=name, 
                                 type_=vmType, 
                                 memory=memory, 
                                 cluster=cluster, 
                                 cpu=cpu, 
                                 template=template) 
             
            newVm = self._session.vms.add(ovirtVMParam)
            
            #stackutils.delete_port(port_id)
                                   
            nicName = 'nic-1' 
            macparam = params.MAC(address=mac) 
            network = self._session.networks.get(name='ovirtmgmt') # ovirtmgmt, Net1
            nicInterface = 'virtio' 
            nic = params.NIC(name=nicName, 
                             interface=nicInterface, 
                             #mac=macparam, 
                             network=network) 
            
            newNic = newVm.nics.add(nic) 
            
            '''
            instance_root_gb = instance['root_gb']
            dl = template.disks.list()
            template_disksize = 0
            for d in dl:
                template_disksize += d.get_size()
                
            template_diskGB = template_disksize / GB
            pending_diskGB = (instance_root_gb - template_diskGB)
            
            if pending_diskGB > 0:
                domain = self._engine.storagedomains.get('DataNFS')
                storageDomain = params.StorageDomains(storage_domain=[domain])
                #volume_size = volume['size']
                size = pending_diskGB * pow(2, 30) 
                diskType = 'data' 
                diskFormat = 'cow' 
                diskInterface = 'virtio' 
                sparse = True 
                bootable = False
                vol_name = 'RootDisk'
                
                newVm.disks.add(params.Disk(
                               name=vol_name,
                               storage_domains=storageDomain,
                               size=size, 
                               type_=diskType,
                               interface=diskInterface, 
                               format=diskFormat, 
                               #sparse=FLAGS.ovirt_engine_sparse,
                               sparse=sparse,
                               bootable=bootable))
                
            '''
            while self._session.vms.get(name).status.state != 'down':
                time.sleep(3)
            try:
                newVm.start()
            except Exception as e:
                #print " ERROR....VM is not able to start : ", str(e)
                newVm.delete()
                raise Exception

            while self._session.vms.get(name).status.state != 'up':
                time.sleep(3)

        except Exception as e:
            raise Exception
        
    def attach_disk(self, instance, volume):
        """attach a volume."""
        try:
            vm = self._session.vms.get(name=instance)
            disk = self._session.disks.get(volume)
            o = vm.disks.add(disk)
            o.activate()
            #pass
        except Exception as e:
               LOG.debug(_("disk attach error %s" %str(e) ))
    
    def detach_disk(self, instance, volume):
        """detach a volume."""
        try:
            vm = self._session.vms.get(name=instance)
            disk = vm.disks.get(name=volume)
            detach = params.Action(detach=True)
            disk.delete(action=detach)
        except Exception as e:
            LOG.debug(_("disk detach error %s" %str(e) ))

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
    
    
