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
        puts response.methods
        Serialization.nsg_from_xml(response)
      end

      def delete_network_security_group(nsg_name)
        path = "/services/networking/networksecuritygroups/#{nsg_name}"
        client.management_request(:delete, path).call
      end

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

      def add_network_security_group_to_role(nsg_name, params)
        path = "/services/hostedservices/#{params[:cloud_service_name]}/deployments/#{params[:deployment_name]}/roles/#{params[:role_name]}/networksecuritygroups"
        puts path
        body = Serialization.add_nsg_to_role_to_xml(nsg_name)
        puts body
        client.management_request(:post, path, body).call
      end

      def remove_network_security_group_from_role(nsg_name, params)
        path = "/services/hostedservices/#{params[:cloud_service_name]}/deployments/#{params[:deployment_name]}/roles/#{params[:role_name]}/networkingsecuritygroups/#{nsg_name}"
        client.management_request(:delete, path).call
      end

      def get_network_security_group_from_role(params)
        path = "/services/hostedservices/#{params[:cloud_service_name]}/deployments/#{params[:deployment_name]}/roles/#{params[:role_name]}/networksecuritygroups"

        response = client.management_request(:get, path).call
        Serialization.get_nsg_from_role_from_xml(response)
      end
    end
  end
end