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
A connection to the RHEVM/Ovirt platform.

**Related Flags**

:ovirtapi_uri : Url for connection to Rhevm/oVirt
:ovirtapi_username : Username for connection to Rhevm/oVirt
:ovirtapi_password : Password for connection to Rhevm/oVirt
:ovirtapi_host_ip : host ip for connection to Rhevm/oVirt

"""
import time
import ConfigParser
from eventlet import event
from oslo.config import cfg
from nova import utils
from nova import context
from nova.virt import driver
from nova import conductor
from nova import exception
from nova.openstack.common import rpc
from nova.openstack.common import jsonutils
from nova.openstack.common import importutils
from nova.openstack.common import log as logging
from nova.openstack.common.gettextutils import _

from ovirtsdk.api import API
from ovirtsdk.xml import params
from nova.virt.ovirtapi import vmops

LOG = logging.getLogger(__name__)
""" This are the various flags that we are reading from the nova.conf, nova-compute.conf"""
ovirtapi_opts = [
    cfg.StrOpt('ovirtapi_uri',
               default=None,
               help='Url for connection to Rhevm/oVirt'),
    cfg.StrOpt('ovirtapi_host_name',
               default=None,
               help='Hostname for connection to Rhevm/oVirt'),
    cfg.StrOpt('ovirtapi_host_ip',
               default=None,
               help='Host IP for connection to Rhevm/oVirt'),
    cfg.StrOpt('ovirtapi_username',
               default=None,
               help='Username for connection to Rhevm/oVirt'),
    cfg.StrOpt('ovirtapi_password',
               default=None,
               help='Password for connection to Rhevm/oVirt'),
]

CONF = cfg.CONF
CONF.register_opts(ovirtapi_opts)

TIME_BETWEEN_API_CALL_RETRIES = 2.0


class Failure(Exception):
    """Base Exception class for handling task failures."""

    def __init__(self, details):
        self.details = details
        print self.details

    def __str__(self):
        return str(self.details)


class oVirtDriver(driver.ComputeDriver):

    """The Rhevm/oVirt connection object."""

    def __init__(self, virtapi, read_only=False, scheme="https"):
        LOG.debug(" Welcome to oVirt ")
        super(oVirtDriver, self).__init__(virtapi)
        self._host_state = None
        self.read_only = read_only
        # rhevm_uri = CONF.rhevmapi_uri
        ovirt_host_name = CONF.ovirtapi_host_name
        # rhevm_host_ip = CONF.rhevmapi_host_ip
        ovirt_username = CONF.ovirtapi_username
        ovirt_password = CONF.ovirtapi_password

        ovirt_uri = "https://" + ovirt_host_name + ":443/api"
        
        if (ovirt_uri or ovirt_username or ovirt_password) is None:
            raise Exception(_("Must specify ovirtapi_uri,"
                              "ovirtapi_username "
                              "and ovirtapi_password to use"))

        self._session = API(
            url=ovirt_uri, username=ovirt_username, password=ovirt_password,
            insecure=True)
        LOG.debug("Connected to oVirt Successful")
        self._vmops = vmops.oVirtOps(self._session)

    def list_instances(self):
        """List the instances in RHEV-M/oVirt."""
        return self._vmops.list_instances()

    def spawn(self, context, instance, image_meta, injected_files,
              admin_password, network_info=None, block_device_info=None):
        """Create a new instance in RHEVM/oVirt"""
        self._vmops.spawn(context, instance, image_meta, network_info)

    def reboot(self, context, instance, network_info, reboot_type,
               block_device_info=None, bad_volumes_callback=None):
        """Reboot an instance in RHEV-M/oVirt"""
        self._vmops.reboot(instance, network_info)

    def destroy(self, instance, network_info, block_device_info=None,
                destroy_disks=True, context=None):
        """Destroy an instance in RHEV-M/oVirt."""
        instance_name = instance['display_name']
        self._vmops.destroy(instance_name, network_info)

    def suspend(self, instance):
        """Suspend the specified instance."""
        instance_name = instance['display_name']
        self._vmops.suspend(instance_name)

    def resume(self, context, instance, network_info, block_device_info=None):
        """Resume the suspended VM instance."""
        instance_name = instance['display_name']
        self._vmops.resume(instance_name)

    def get_info(self, instance):
        """Get the current status of an instance, by name (not ID!)

        Returns a dict containing:

        :state:           the running state, one of the power_state codes
        :max_mem:         (int) the maximum memory in KBytes allowed
        :mem:             (int) the memory in KBytes used by the domain
        :num_cpu:         (int) the number of virtual CPUs for the domain
        :cpu_time:        (int) the CPU time used in nanoseconds
        """
        instance_name = instance['display_name']
        return self._vmops.get_info(instance_name)

    def legacy_nwinfo(self):
        """True if the driver requires the legacy network_info format."""
        # TODO(tr3buchet): update all subclasses and remove this method and
        # related helpers.
        return True

    def power_off(self, instance):
        """Power off the specified instance."""
        instance_name = instance['display_name']
        self._vmops.power_off(instance_name)

    def power_on(self, context, instance, network_info,
                 block_device_info=None):
        """Power on the specified instance."""
        instance_name = instance['display_name']
        self._vmops.power_on(instance_name)

    def snapshot(self, context, instance, image_id):
        """Create snapshot from a running VM instance."""
        pass

    def init_host(self, host):
        """Initialize anything that is necessary for the driver to function,
        including catching up with currently running VM's on the given host."""
        # TODO(Vek): Need to pass context in for access to auth_token
        pass

    def get_console_pool_info(self, console_type):
        # TODO(Vek): Need to pass context in for access to auth_token
        pass

    def get_console_output(self, instance):
        # TODO(Vek): Need to pass context in for access to auth_token
        pass

    def get_vnc_console(self, instance):
        # TODO(Vek): Need to pass context in for access to auth_token
        pass

    def get_spice_console(self, instance):
        # TODO(Vek): Need to pass context in for access to auth_token
        pass

    def get_diagnostics(self, instance):
        """Return data about VM diagnostics."""
        # TODO(Vek): Need to pass context in for access to auth_token
        pass

    def get_all_volume_usage(self, context, compute_host_bdms):
        """Return usage info for volumes attached to vms on
           a given host"""
        pass

    def get_host_ip_addr(self):
        """
        Retrieves the IP address of the dom0
        """
        # TODO(Vek): Need to pass context in for access to auth_token
        pass

    #def attach_volume(self, connection_info, instance, mountpoint):
    
    def attach_volume(self, context, connection_info, instance, mountpoint,
                      encryption=None):
        """Attach the disk to the instance at mountpoint using info."""
        instance_name = instance['display_name']
        data = connection_info['data']
        volume_name = data['volume_name']
        
        self._vmops.attach_disk(instance_name,volume_name)

    def detach_volume(self, connection_info, instance, mountpoint,
                      encryption=None):
        """Detach the disk attached to the instance."""
        instance_name = instance['display_name']
        data = connection_info['data']
        volume_name = data['volume_name']
        
        self._vmops.detach_disk(instance_name,volume_name)

    def attach_interface(self, instance, image_meta, network_info):
        """Attach an interface to the instance."""
        pass

    def detach_interface(self, instance, network_info):
        """Detach an interface from the instance."""
        pass

    def migrate_disk_and_power_off(self, context, instance, dest,
                                   instance_type, network_info,
                                   block_device_info=None):
        """
        Transfers the disk of a running instance in multiple phases, turning
        off the instance before the end.
        """
        pass

    def finish_migration(self, context, migration, instance, disk_info,
                         network_info, image_meta, resize_instance,
                         block_device_info=None):
        """Completes a resize, turning on the migrated instance

        :param network_info:
           :py:meth:`~nova.network.manager.NetworkManager.get_instance_nw_info`
        :param image_meta: image object returned by nova.image.glance that
                           defines the image from which this instance
                           was created
        """
        pass

    def confirm_migration(self, migration, instance, network_info):
        """Confirms a resize, destroying the source VM."""
        # TODO(Vek): Need to pass context in for access to auth_token
        pass

    def finish_revert_migration(self, instance, network_info,
                                block_device_info=None):
        """Finish reverting a resize, powering back on the instance."""
        # TODO(Vek): Need to pass context in for access to auth_token
        pass

    def pause(self, instance):
        """Pause the specified instance."""
        pass

    def unpause(self, instance):
        """Unpause paused VM instance."""
        pass

    def soft_delete(self, instance):
        """Soft delete the specified instance."""
        pass

    def resume_state_on_host_boot(self, context, instance, network_info,
                                  block_device_info=None):
        """resume guest state when a host is booted."""
        pass

    def rescue(self, context, instance, network_info, image_meta,
               rescue_password):
        """Rescue the specified instance."""
        pass

    def unrescue(self, instance, network_info):
        """Unrescue the specified instance."""
        # TODO(Vek): Need to pass context in for access to auth_token
        pass

    def restore(self, instance):
        """Restore the specified instance."""
        pass

    def pre_live_migration(self, ctxt, instance_ref,
                           block_device_info, network_info,
                           migrate_data=None):
        """Prepare an instance for live migration

        :param ctxt: security context
        :param instance_ref: instance object that will be migrated
        :param block_device_info: instance block device information
        :param network_info: instance network information
        :param migrate_data: implementation specific data dict.
        """
        pass

    def pre_block_migration(self, ctxt, instance_ref, disk_info):
        """Prepare a block device for migration

        :param ctxt: security context
        :param instance_ref: instance object that will have its disk migrated
        :param disk_info: information about disk to be migrated (as returned
                          from get_instance_disk_info())
        """
        pass

    def live_migration(self, ctxt, instance_ref, dest,
                       post_method, recover_method, block_migration=False,
                       migrate_data=None):
        """Live migration of an instance to another host.

        :params ctxt: security context
        :params instance_ref:
            nova.db.sqlalchemy.models.Instance object
            instance object that is migrated.
        :params dest: destination host
        :params post_method:
            post operation method.
            expected nova.compute.manager.post_live_migration.
        :params recover_method:
            recovery method when any exception occurs.
            expected nova.compute.manager.recover_live_migration.
        :params block_migration: if true, migrate VM disk.
        :params migrate_data: implementation specific params.

        """
        pass

    def post_live_migration_at_destination(self, ctxt, instance_ref,
                                           network_info,
                                           block_migration=False,
                                           block_device_info=None):
        """Post operation of live migration at destination host.

        :param ctxt: security context
        :param instance_ref: instance object that is migrated
        :param network_info: instance network information
        :param block_migration: if true, post operation of block_migration.
        """
        pass

    def check_can_live_migrate_destination(self, ctxt, instance_ref,
                                           src_compute_info, dst_compute_info,
                                           block_migration=False,
                                           disk_over_commit=False):
        """Check if it is possible to execute live migration.

        This runs checks on the destination host, and then calls
        back to the source host to check the results.

        :param ctxt: security context
        :param instance_ref: nova.db.sqlalchemy.models.Instance
        :param src_compute_info: Info about the sending machine
        :param dst_compute_info: Info about the receiving machine
        :param block_migration: if true, prepare for block migration
        :param disk_over_commit: if true, allow disk over commit
        """
        pass

    def check_can_live_migrate_destination_cleanup(self, ctxt,
                                                   dest_check_data):
        """Do required cleanup on dest host after check_can_live_migrate calls

        :param ctxt: security context
        :param dest_check_data: result of check_can_live_migrate_destination
        """
        pass

    def check_can_live_migrate_source(self, ctxt, instance_ref,
                                      dest_check_data):
        """Check if it is possible to execute live migration.

        This checks if the live migration can succeed, based on the
        results from check_can_live_migrate_destination.

        :param context: security context
        :param instance_ref: nova.db.sqlalchemy.models.Instance
        :param dest_check_data: result of check_can_live_migrate_destination
        """
        pass

    def refresh_security_group_rules(self, security_group_id):
        """This method is called after a change to security groups.

        All security groups and their associated rules live in the datastore,
        and calling this method should apply the updated rules to instances
        running the specified security group.

        An error should be raised if the operation cannot complete.

        """
        # TODO(Vek): Need to pass context in for access to auth_token
        pass

    def refresh_security_group_members(self, security_group_id):
        """This method is called when a security group is added to an instance.

        This message is sent to the virtualization drivers on hosts that are
        running an instance that belongs to a security group that has a rule
        that references the security group identified by `security_group_id`.
        It is the responsibility of this method to make sure any rules
        that authorize traffic flow with members of the security group are
        updated and any new members can communicate, and any removed members
        cannot.

        Scenario:
            * we are running on host 'H0' and we have an instance 'i-0'.
            * instance 'i-0' is a member of security group 'speaks-b'
            * group 'speaks-b' has an ingress rule that authorizes group 'b'
            * another host 'H1' runs an instance 'i-1'
            * instance 'i-1' is a member of security group 'b'

            When 'i-1' launches or terminates we will receive the message
            to update members of group 'b', at which time we will make
            any changes needed to the rules for instance 'i-0' to allow
            or deny traffic coming from 'i-1', depending on if it is being
            added or removed from the group.

        In this scenario, 'i-1' could just as easily have been running on our
        host 'H0' and this method would still have been called.  The point was
        that this method isn't called on the host where instances of that
        group are running (as is the case with
        :py:meth:`refresh_security_group_rules`) but is called where references
        are made to authorizing those instances.

        An error should be raised if the operation cannot complete.

        """
        # TODO(Vek): Need to pass context in for access to auth_token
        pass

    def refresh_provider_fw_rules(self):
        """This triggers a firewall update based on database changes.

        When this is called, rules have either been added or removed from the
        datastore.  You can retrieve rules with
        :py:meth:`nova.db.provider_fw_rule_get_all`.

        Provider rules take precedence over security group rules.  If an IP
        would be allowed by a security group ingress rule, but blocked by
        a provider rule, then packets from the IP are dropped.  This includes
        intra-project traffic in the case of the allow_project_net_traffic
        flag for the libvirt-derived classes.

        """
        # TODO(Vek): Need to pass context in for access to auth_token
        pass

    def reset_network(self, instance):
        """reset networking for specified instance."""
        # TODO(Vek): Need to pass context in for access to auth_token
        pass

    def ensure_filtering_rules_for_instance(self, instance_ref, network_info):
        """Setting up filtering rules and waiting for its completion.

        To migrate an instance, filtering rules to hypervisors
        and firewalls are inevitable on destination host.
        ( Waiting only for filtering rules to hypervisor,
        since filtering rules to firewall rules can be set faster).

        Concretely, the below method must be called.
        - setup_basic_filtering (for nova-basic, etc.)
        - prepare_instance_filter(for nova-instance-instance-xxx, etc.)

        to_xml may have to be called since it defines PROJNET, PROJMASK.
        but libvirt migrates those value through migrateToURI(),
        so , no need to be called.

        Don't use thread for this method since migration should
        not be started when setting-up filtering rules operations
        are not completed.

        :params instance_ref: nova.db.sqlalchemy.models.Instance object

        """
        # TODO(Vek): Need to pass context in for access to auth_token
        pass

    def filter_defer_apply_on(self):
        """Defer application of IPTables rules."""
        pass

    def filter_defer_apply_off(self):
        """Turn off deferral of IPTables rules and apply the rules now."""
        pass

    def unfilter_instance(self, instance, network_info):
        """Stop filtering instance."""
        # TODO(Vek): Need to pass context in for access to auth_token
        pass

    def set_admin_password(self, context, instance_id, new_pass=None):
        """
        Set the root password on the specified instance.

        The first parameter is an instance of nova.compute.service.Instance,
        and so the instance is being specified as instance.name. The second
        parameter is the value of the new password.
        """
        pass

    def inject_file(self, instance, b64_path, b64_contents):
        """
        Writes a file on the specified instance.

        The first parameter is an instance of nova.compute.service.Instance,
        and so the instance is being specified as instance.name. The second
        parameter is the base64-encoded path to which the file is to be
        written on the instance; the third is the contents of the file, also
        base64-encoded.
        """
        # TODO(Vek): Need to pass context in for access to auth_token
        pass

    def change_instance_metadata(self, context, instance, diff):
        """
        Applies a diff to the instance metadata.

        This is an optional driver method which is used to publish
        changes to the instance's metadata to the hypervisor.  If the
        hypervisor has no means of publishing the instance metadata to
        the instance, then this method should not be implemented.
        """
        pass

    def inject_network_info(self, instance, nw_info):
        """inject network info for specified instance."""
        # TODO(Vek): Need to pass context in for access to auth_token
        pass

    def poll_rebooting_instances(self, timeout, instances):
        """Poll for rebooting instances

        :param timeout: the currently configured timeout for considering
                        rebooting instances to be stuck
        :param instances: instances that have been in rebooting state
                          longer than the configured timeout
        """
        # TODO(Vek): Need to pass context in for access to auth_token
        pass

    def host_power_action(self, host, action):
        """Reboots, shuts down or powers up the host."""
        pass

    def host_maintenance_mode(self, host, mode):
        """Start/Stop host maintenance window. On start, it triggers
        guest VMs evacuation."""
        pass

    def set_host_enabled(self, host, enabled):
        """Sets the specified host's ability to accept new instances."""
        # TODO(Vek): Need to pass context in for access to auth_token
        pass

    def get_host_uptime(self, host):
        """Returns the result of calling "uptime" on the target host."""
        # TODO(Vek): Need to pass context in for access to auth_token
        pass

    def plug_vifs(self, instance, network_info):
        """Plug VIFs into networks."""
        # TODO(Vek): Need to pass context in for access to auth_token
        pass

    def unplug_vifs(self, instance, network_info):
        """Unplug VIFs from networks."""
        pass

    def block_stats(self, instance_name, disk_id):
        """
        Return performance counters associated with the given disk_id on the
        given instance_name.  These are returned as [rd_req, rd_bytes, wr_req,
        wr_bytes, errs], where rd indicates read, wr indicates write, req is
        the total number of I/O requests made, bytes is the total number of
        bytes transferred, and errs is the number of requests held up due to a
        full pipeline.

        All counters are long integers.

        This method is optional.  On some platforms (e.g. XenAPI) performance
        statistics can be retrieved directly in aggregate form, without Nova
        having to do the aggregation.  On those platforms, this method is
        unused.

        Note that this function takes an instance ID.
        """
        pass

    def interface_stats(self, instance_name, iface_id):
        """
        Return performance counters associated with the given iface_id on the
        given instance_id.  These are returned as [rx_bytes, rx_packets,
        rx_errs, rx_drop, tx_bytes, tx_packets, tx_errs, tx_drop], where rx
        indicates receive, tx indicates transmit, bytes and packets indicate
        the total number of bytes or packets transferred, and errs and dropped
        is the total number of packets failed / dropped.

        All counters are long integers.

        This method is optional.  On some platforms (e.g. XenAPI) performance
        statistics can be retrieved directly in aggregate form, without Nova
        having to do the aggregation.  On those platforms, this method is
        unused.

        Note that this function takes an instance ID.
        """
        pass

    def manage_image_cache(self, context, all_instances):
        """
        Manage the driver's local image cache.

        Some drivers chose to cache images for instances on disk. This method
        is an opportunity to do management of that cache which isn't directly
        related to other calls into the driver. The prime example is to clean
        the cache and remove images which are no longer of interest.
        """
        pass

    def add_to_aggregate(self, context, aggregate, host, **kwargs):
        """Add a compute host to an aggregate."""
        # NOTE(jogo) Currently only used for XenAPI-Pool
        pass

    def remove_from_aggregate(self, context, aggregate, host, **kwargs):
        """Remove a compute host from an aggregate."""
        pass

    def undo_aggregate_operation(self, context, op, aggregate,
                                 host, set_error=True):
        """Undo for Resource Pools."""
        pass

    def get_volume_connector(self, instance):
        """Get connector information for the instance for attaching to volumes.

        Connector information is a dictionary representing the ip of the
        machine that will be making the connection, the name of the iscsi
        initiator and the hostname of the machine as follows::

            {
                'ip': ip,
                'initiator': initiator,
                'host': hostname
            }
        """
        pass

    def get_disk_details(self, cluster_datacenter_id):
        '''get disk details '''
        disk_used = 0
        disk_available = 0
        disk_total = 0
        disk_info = {}
        storagedomains = self._session.datacenters.get(
            id=cluster_datacenter_id).storagedomains.list()
        for storage in storagedomains:
            if(storage.get_master()):
                disk_used = storage.get_used() / (1024 * 1024 * 1024)
                disk_available = storage.get_available() / (1024 * 1024 * 1024)
                disk_total = disk_used + disk_available

        disk_info["disk_used"] = disk_used
        disk_info["disk_available"] = disk_available
        disk_info["disk_total"] = disk_total

        return disk_info

    def get_vcpu_used(self):
        vcpu_used = 0
        return vcpu_used

    def get_hypervisor_version(self):
        hypervisor_version = 62
        return hypervisor_version

    def get_hypervisor_type(self):
        hypervisor_type = 'rhevh'
        return hypervisor_type

    def get_instance_capabilities(self):
        '''get the instance capabilities '''
        instance_cap = list()
        instance_cap = [('i686', 'rhevh', 'hvm', CONF.ovirtapi_host_name), (
            'x86_64', 'rhevh', 'hvm', CONF.ovirtapi_host_name)]
        return instance_cap

    def get_cpu_info(self, cluster, cores):
        '''get the cpu details '''
        cpu_info = dict()
        cpu_info['arch'] = 'x86_64'
        cpuid = cluster.cpu.id
        cpu = str(cpuid).split()
        vendor = cpu[0]
        model = cpu[1] + '_' + cpu[2]
        cpu_info['model'] = model
        cpu_info['vendor'] = vendor

        topology = dict()
        topology['sockets'] = 16
        topology['cores'] = cores
        topology['threads'] = 0
        cpu_info['topology'] = topology

        features = list()
        features = [u'3dnow', u'3dnowext',
                    u'fxsr_opt', u'mmxext', u'hypervisor', u'vme']
        cpu_info['features'] = features

        return jsonutils.dumps(cpu_info)

    def get_ovirtclusterinfo(self, nodename):
        '''get the cluster details '''
        detail = {}

        cluster_total_memory = 0  # in MB
        cluster_free_memory = 0   # in MB
        self.cluster_used_memory = 0  # in MB
        cluster_total_cores = 0
        clusters = self._session.clusters.list()
        for clustername in clusters:
            if(clustername.name == nodename):
                cluster = clustername

        cluster_name = cluster.name
        cluster_id = cluster.id
        cluster_datacenter_id = cluster.data_center.id
        hosts = self._session.hosts.list()
        if hosts is not None:
            for host in hosts:
                hostclusterid = host.cluster.id
                if (cluster_id == hostclusterid)and \
                        (host.status.state == 'up'):
                    cluster_total_cores = cluster_total_cores + \
                        int(host.get_cpu().topology.cores)
                    statistic = host.statistics.list()
                    total_memory = int((statistic[0].values.value[0].datum)
                                       / (1024 * 1024))
                    cluster_total_memory = total_memory + cluster_total_memory
                    used_memory = int((statistic[1].values.value[0].datum)
                                      / (1024 * 1024))
                    self.cluster_used_memory = used_memory + \
                        self.cluster_used_memory
                    cluster_free_memory = cluster_total_memory - \
                        self.cluster_used_memory

        detail["host_memory_total"] = cluster_total_memory
        detail["host_memory_free"] = cluster_free_memory

        self.cpu_info = self.get_cpu_info(cluster, cluster_total_cores)

        detail["cpu_info"] = jsonutils.loads(self.cpu_info)
        detail["vcpus"] = cluster_total_cores
        detail["vcpus_used"] = self.get_vcpu_used()
        detail["hypervisor_hostname"] = cluster_name
        detail["hypervisor_type"] = self.get_hypervisor_type()
        detail["hypervisor_version"] = self.get_hypervisor_version()
        detail["supported_instances"] = self.get_instance_capabilities()

        disk_info = self.get_disk_details(cluster_datacenter_id)
        detail["disk_total"] = disk_info["disk_total"]
        detail["disk_used"] = disk_info["disk_used"]
        detail["disk_available"] = disk_info["disk_available"]

        
        return detail

    def get_available_resource(self, nodename):
        """Retrieve resource info.

        This method is called when nova-compute launches, and
        as part of a periodic task.

        :returns: dictionary describing resources

        """
        cluster_detail = self.get_ovirtclusterinfo(nodename)

        dic = {'vcpus':  cluster_detail["vcpus"],
               'vcpus_used': cluster_detail["vcpus_used"],
               'memory_mb': cluster_detail["host_memory_total"],
               'memory_mb_used': self.cluster_used_memory,
               'hypervisor_type': cluster_detail["hypervisor_type"],
               'hypervisor_version': cluster_detail["hypervisor_version"],
               'hypervisor_hostname': cluster_detail["hypervisor_hostname"],
               'cpu_info': self.cpu_info,
               'local_gb': cluster_detail["disk_total"],
               'local_gb_used': cluster_detail["disk_used"],
               'disk_available_least': cluster_detail["disk_available"]}

        
        return dic


    @property
    def host_state(self):
        if not self._host_state:
            self._host_state = HostState(self.virtapi, self.read_only)
        return self._host_state
    
    def get_available_nodes(self):
        """Returns nodenames of all nodes managed by the compute service.

        This method is for multi compute-nodes support. If a driver supports
        multi compute-nodes, this method returns a list of nodenames managed
        by the service. Otherwise, this method should return
        [hypervisor_hostname].
        """
        stats = self.get_host_stats(refresh=True)
        if not isinstance(stats, list):
            stats = [stats]
        return [s['hypervisor_hostname'] for s in stats]

    
    def get_host_stats(self, refresh=False):
        """Return the current state of the host. If 'refresh' is
           True, run the update first."""
        return self.host_state.get_host_stats(refresh=refresh)


class HostState(object):

    """Manages information about cluster in Rhevm/oVirt"""
    def __init__(self, virtapi, read_only):
        super(HostState, self).__init__()
        self.read_only = read_only
        self._stats = {}
        self.connection = None
        self.virtapi = virtapi
        self.update_status()

    def get_host_stats(self, refresh=False):
        """Return the current state of the host.

        If 'refresh' is True, run update the stats first."""
        if refresh:
            self.update_status()
        return self._stats

    def update_status(self):
        """Retrieve status info from Rhevm/Ovirt"""

        if self.connection is None:
            self.connection = oVirtDriver(self.virtapi, self.read_only)

        data = []
        clusters = self.connection._session.clusters.list()
        if clusters is not None:
            for nodename in clusters:
                details = self.connection.get_ovirtclusterinfo(nodename.name)
                data.append(details)
        self._stats = data

        return data
