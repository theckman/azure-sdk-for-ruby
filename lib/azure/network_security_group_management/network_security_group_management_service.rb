require 'azure/core/error'
require 'azure/network_security_group_management/serialization'
include Azure::NetworkSecurityGroupManagement

module Azure
  module NetworkSecurityGroupManagement
    class NetworkSecurityGroupManagementService < BaseManagement::BaseManagementService
      include  Azure::Core::Utility

      def list_network_security_groups
        path = '/services/networking/networksecuritygroups'

       request = client.management_request(:get, path)

       request.warn = true
       response = request.call

       Serialization.nsg_list_from_xml(response)
      end

      # Public: creates a network security group using the provided configuration
      #
      # === Attributes
      # * +nsg_name+      - String. Name of the NetworkSecurityGroup
      # * +params+        - Hash.   Options needed to create the NSG
      #
      # === Params
      #
      # Accepted key/value pairs are:
      # * +name+        - String.   Required. Specifies the name of the network security group.
      # * +location+    - String.   Required. Specifies the location where the network security group is created. To see the available locations, you can use List Locations.
      # * +label+       - String.   Optional. Specifies an identifier for the network security group. The label can be up to 1024 characters long. The label can be used for tracking purposes.
      def create_network_security_group(nsg_name, params)
        params[:label] = params[:label] || ''
        params[:name] = nsg_name

        begin
          validate_location(params[:location])
        rescue StandardError => e
          Azure::Loggerx.error_with_exit(e.message)
        end

        params[:label] = params[:label][0...1024] if params[:label].size > 1024

        path = '/services/networking/networksecuritygroups'
        body = Serialization.create_nsg_to_xml(params)

        client.management_request(:post, path, body).call
        get_network_security_group(nsg_name)
      end

      def get_network_security_group(nsg_name)
        path = "/services/networking/networksecuritygroups/#{nsg_name}?detaillevel=Full"
        request = client.management_request(:get, path)
        response = request.call
        Serialization.nsg_from_xml(response)
      end

      def delete_network_security_group(nsg_name)
        path = "/services/networking/networksecuritygroups/#{nsg_name}"
        client.management_request(:delete, path).call
      end

      # Public: create a network security rule on an NSG
      #
      # === Attributes
      # * +nsg_name+      - String. Name of the NetworkSecurityGroup
      # * +params+        - Hash.   Options needed to create the NSG
      #
      # === Params
      #
      # Accepted key/value pairs are:
      # * +name+                        - String.   Specifies the name of the network security group rule.
      # * +type+                        - Symbol.   Specifies the type of the network security rule. Possible values are: :inbound, :outbound
      # * +priority+                    - String.   Specifies the priority of the network security rule. Rules with lower priority are evaluated first. This value can be between 100 and 4096.
      # * +action+                      - Symbol.   Specifies the action that is performed when the network security rule is matched. Possible values are: :allow, :deny
      # * +source_address_prefix+       - String.   Specifies the CIDR or source IP range. An asterisk (*) can also be used to match all source IPs.
      # * +source_port_range+           - String.   Specifies the source port or range. This value can be between 0 and 65535. An asterisk (*) can also be used to match all ports.
      # * +destination_addresss_prefix+ - String.   Specifies the CIDR or destination IP range. An asterisk (*) can also be used to match all destination IPs.
      # * +destination_port_range+      - String.   Specifies the destination port or range. This value can be between 0 and 65535. An asterisk (*) can also be used to match all ports.
      # * +protocol+                    - Symbol.   Specifies the protocol of the network security rule. Possible values are: :tcp, :udp, :any
      def set_network_security_rule(nsg_name, params)
        # if the NetworkSecurityGroup name is nil/empty
        # or the rule name is, explode!
        raise Azure::Core::Error, 'NetworkSecurityGroup name must not be empty' if nsg_name.nil? || nsg_name.empty?
        raise Azure::Core::Error, 'Rule name must not be empty' if params[:name].nil? || params[:name].empty?

        path = "/services/networking/networksecuritygroups/#{nsg_name}/rules/#{params[:name]}"
        body = Serialization.nsg_rule_to_xml(params)
        client.management_request(:put, path, body).call
        get_network_security_rule(nsg_name, params[:name])
      end

      def delete_network_security_rule(nsg_name, rule_name)
        path = "/services/networking/networksecuritygroups/#{nsg_name}/rules/#{rule_name}"
        client.management_request(:delete, path).call
      end

      def get_network_security_rule(nsg_name, rule_name)
        sg = get_network_security_group(nsg_name)
        sg.rules.each { |r| return r if r.name == rule_name }
        nil
      end

      # Public: add a network security group to a role
      #
      # === Attributes
      # * +nsg_name+      - String. Name of the NetworkSecurityGroup
      # * +params+        - Hash.   Options needed to create the NSG
      #
      # === Params
      #
      # Accepted key/value pairs are:
      # * +cloud_service_name+  - String.   The cloud service name of VM where you want to add the NSG.
      # * +deployment_name+     - String.   The deployment name of the VM where you want to add the NSG.
      # * +role_name+           - String.   The name of the VM you want to add the NSG on.
      def add_network_security_group_to_role(nsg_name, params)
        path = "/services/hostedservices/#{params[:cloud_service_name]}/deployments/#{params[:deployment_name]}/roles/#{params[:role_name]}/networksecuritygroups"
        body = Serialization.add_nsg_to_role_to_xml(nsg_name)
        client.management_request(:post, path, body).call
      end

      # Public: remove a network security group to a role
      #
      # === Attributes
      # * +nsg_name+      - String. Name of the NetworkSecurityGroup
      # * +params+        - Hash.   Options needed to create the NSG
      #
      # === Params
      #
      # Accepted key/value pairs are:
      # * +cloud_service_name+  - String.   The cloud service name of VM where you want to remove the NSG.
      # * +deployment_name+     - String.   The deployment name of the VM where you want to remove the NSG.
      # * +role_name+           - String.   The name of the VM you want to remove the NSG from.
      def remove_network_security_group_from_role(nsg_name, params)
        path = "/services/hostedservices/#{params[:cloud_service_name]}/deployments/#{params[:deployment_name]}/roles/#{params[:role_name]}/networksecuritygroups/#{nsg_name}"
        client.management_request(:delete, path).call
      end

      # Public: get the network security groups of a node
      #
      # === Attributes
      # * +params+        - Hash.   Options needed to create the NSG
      #
      # === Params
      #
      # Accepted key/value pairs are:
      # * +cloud_service_name+  - String.   The cloud service name of VM where you want to get the NSG.
      # * +deployment_name+     - String.   The deployment name of the VM where you want to get the NSG.
      # * +role_name+           - String.   The name of the VM you want to get the NSG from.
      def get_network_security_group_from_role(params)
        path = "/services/hostedservices/#{params[:cloud_service_name]}/deployments/#{params[:deployment_name]}/roles/#{params[:role_name]}/networksecuritygroups"

        response = client.management_request(:get, path).call
        Serialization.get_nsg_from_role_from_xml(response)
      end
    end
  end
end